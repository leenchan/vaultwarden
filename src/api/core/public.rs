use chrono::Utc;
use rocket::{
    request::{FromRequest, Outcome},
    serde::json::Json,
    Request, Route,
};

use std::collections::HashSet;

use crate::{
    api::{EmptyResult, JsonResult},
    auth,
    db::{
        models::{
            Group, GroupUser, Invitation, Membership, MembershipId, MembershipStatus, MembershipType, Organization,
            OrganizationApiKey, OrganizationId, User,
        },
        DbConn,
    },
    mail, CONFIG,
};
use data_encoding::BASE64;
use serde::Deserialize;
use serde_json::json;

pub fn routes() -> Vec<Route> {
    routes![ldap_import, get_public_members, bulk_confirm_public_members]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportGroupData {
    name: String,
    external_id: String,
    member_external_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportUserData {
    email: String,
    external_id: String,
    deleted: bool,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportData {
    groups: Vec<OrgImportGroupData>,
    members: Vec<OrgImportUserData>,
    overwrite_existing: bool,
    // largeImport: bool, // For now this will not be used, upstream uses this to prevent syncs of more then 2000 users or groups without the flag set.
}

#[post("/public/organization/import", data = "<data>")]
async fn ldap_import(data: Json<OrgImportData>, token: PublicToken, conn: DbConn) -> EmptyResult {
    // Most of the logic for this function can be found here
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Services/Implementations/OrganizationService.cs#L1203

    let org_id = token.0;
    let data = data.into_inner();

    for user_data in &data.members {
        let mut user_created: bool = false;
        if user_data.deleted {
            // If user is marked for deletion and it exists, revoke it
            if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
                // Only revoke a user if it is not the last confirmed owner
                let revoked = if member.atype == MembershipType::Owner
                    && member.status == MembershipStatus::Confirmed as i32
                {
                    if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
                        warn!("Can't revoke the last owner");
                        false
                    } else {
                        member.revoke()
                    }
                } else {
                    member.revoke()
                };

                let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
                if revoked || ext_modified {
                    member.save(&conn).await?;
                }
            }
        // If user is part of the organization, restore it
        } else if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
            let restored = member.restore();
            let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
            if restored || ext_modified {
                member.save(&conn).await?;
            }
        } else {
            // If user is not part of the organization
            let mut user = match User::find_by_mail(&user_data.email, &conn).await {
                Some(u) => u, // exists in vaultwarden
                None => {
                    // User does not exist yet
                    let mut new_user = User::new(&user_data.email, None);
                    new_user.save(&conn).await?;

                    if !CONFIG.mail_enabled() {
                        Invitation::new(&new_user.email).save(&conn).await?;
                    }
                    user_created = true;
                    new_user
                }
            };
            
            // If password and key are provided, set them
            // This allows setting master password during import
            if let (Some(password), Some(key)) = (&user_data.password, &user_data.key) {
                if !password.is_empty() && !key.is_empty() {
                    // Generate master_password_hash similar to frontend
                    // Step 1: Generate masterKey using client KDF (PBKDF2 with email as salt)
                    let email_salt = user.email.trim().to_lowercase();
                    let client_kdf_iter = user.client_kdf_iter;
                    let master_key = crate::crypto::hash_password(password.as_bytes(), email_salt.as_bytes(), client_kdf_iter as u32);
                    
                    // Step 2: Generate master_password_hash using masterKey and password
                    // hashMasterKey: PBKDF2(masterKey.inner().encryptionKey, masterPassword, 1)
                    let master_password_hash_bytes = crate::crypto::hash_password(password.as_bytes(), &master_key, 1);
                    
                    // Step 3: Convert to base64 string (as client would send)
                    let master_password_hash = BASE64.encode(&master_password_hash_bytes);
                    
                    // Step 4: Set password and key
                    user.set_password(&master_password_hash, Some(key.clone()), false, None);
                    user.save(&conn).await?;
                }
            }
            // Always set status to Accepted to skip the invitation acceptance step
            let member_status = MembershipStatus::Accepted as i32;

            let (org_name, org_email) = match Organization::find_by_uuid(&org_id, &conn).await {
                Some(org) => (org.name, org.billing_email),
                None => err!("Error looking up organization"),
            };

            let mut new_member = Membership::new(user.uuid.clone(), org_id.clone(), Some(org_email.clone()));
            new_member.set_external_id(Some(user_data.external_id.clone()));
            new_member.access_all = false;
            new_member.atype = MembershipType::User as i32;
            new_member.status = member_status;

            new_member.save(&conn).await?;

            if CONFIG.mail_enabled() {
                if let Err(e) =
                    mail::send_invite(&user, org_id.clone(), new_member.uuid.clone(), &org_name, Some(org_email)).await
                {
                    // Upon error delete the user, invite and org member records when needed
                    if user_created {
                        user.delete(&conn).await?;
                    } else {
                        new_member.delete(&conn).await?;
                    }

                    err!(format!("Error sending invite: {e:?} "));
                }
            }
        }
    }

    if CONFIG.org_groups_enabled() {
        for group_data in &data.groups {
            let group_uuid = match Group::find_by_external_id_and_org(&group_data.external_id, &org_id, &conn).await {
                Some(group) => group.uuid,
                None => {
                    let mut group = Group::new(
                        org_id.clone(),
                        group_data.name.clone(),
                        false,
                        Some(group_data.external_id.clone()),
                    );
                    group.save(&conn).await?;
                    group.uuid
                }
            };

            GroupUser::delete_all_by_group(&group_uuid, &conn).await?;

            for ext_id in &group_data.member_external_ids {
                if let Some(member) = Membership::find_by_external_id_and_org(ext_id, &org_id, &conn).await {
                    let mut group_user = GroupUser::new(group_uuid.clone(), member.uuid.clone());
                    group_user.save(&conn).await?;
                }
            }
        }
    } else {
        warn!("Group support is disabled, groups will not be imported!");
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.overwrite_existing {
        // Generate a HashSet to quickly verify if a member is listed or not.
        let sync_members: HashSet<String> = data.members.into_iter().map(|m| m.external_id).collect();
        for member in Membership::find_by_org(&org_id, &conn).await {
            if let Some(ref user_external_id) = member.external_id {
                if !sync_members.contains(user_external_id) {
                    if member.atype == MembershipType::Owner && member.status == MembershipStatus::Confirmed as i32 {
                        // Removing owner, check that there is at least one other confirmed owner
                        if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1
                        {
                            warn!("Can't delete the last owner");
                            continue;
                        }
                    }
                    member.delete(&conn).await?;
                }
            }
        }
    }

    Ok(())
}

#[get("/public/organization/members")]
async fn get_public_members(token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    let mut members_json = Vec::new();
    
    for m in Membership::find_by_org(&org_id, &conn).await {
        // Get user info
        let user = match User::find_by_uuid(&m.user_uuid, &conn).await {
            Some(u) => u,
            None => continue,
        };
        
        // Determine status name
        let status_name = match MembershipStatus::from_i32(m.status) {
            Some(MembershipStatus::Invited) => "Invited",
            Some(MembershipStatus::Accepted) => "Accepted",
            Some(MembershipStatus::Confirmed) => "Confirmed",
            Some(MembershipStatus::Revoked) => "Revoked",
            None => "Unknown",
        };
        
        members_json.push(json!({
            "id": m.uuid,
            "userId": m.user_uuid,
            "email": user.email,
            "name": user.name,
            "status": m.status,
            "statusName": status_name,
            "type": m.atype,
            "accessAll": m.access_all,
            "externalId": m.external_id,
        }));
    }

    Ok(Json(json!({
        "data": members_json,
        "object": "list",
        "continuationToken": null,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkConfirmPublicData {
    member_ids: Vec<MembershipId>,
}

#[post("/public/organization/members/confirm", data = "<data>")]
async fn bulk_confirm_public_members(
    data: Json<BulkConfirmPublicData>,
    token: PublicToken,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    let data = data.into_inner();
    let member_ids = data.member_ids.clone();
    let total_count = member_ids.len();
    
    let mut results = Vec::new();
    let mut confirmed_count = 0;
    let mut failed_count = 0;
    
    for member_id in &member_ids {
        let result = match Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await {
            Some(mut member) => {
                // Check if member is in Accepted status (needs confirmation)
                if member.status == MembershipStatus::Accepted as i32 {
                    // Update status to Confirmed
                    // Note: akey should be set by the user when they first access the organization
                    // We cannot generate a valid encrypted akey here because we don't have the user's encryption key
                    // If akey is empty, it will remain empty and the frontend will handle setting it
                    // when the user actually accesses the organization
                    member.status = MembershipStatus::Confirmed as i32;
                    
                    match member.save(&conn).await {
                        Ok(_) => {
                            confirmed_count += 1;
                            json!({
                                "id": member_id,
                                "status": "success",
                                "message": "Member confirmed successfully"
                            })
                        }
                        Err(e) => {
                            failed_count += 1;
                            json!({
                                "id": member_id,
                                "status": "error",
                                "message": format!("Failed to save: {}", e)
                            })
                        }
                    }
                } else {
                    let status_name = match MembershipStatus::from_i32(member.status) {
                        Some(MembershipStatus::Invited) => "Invited",
                        Some(MembershipStatus::Accepted) => "Accepted",
                        Some(MembershipStatus::Confirmed) => "Confirmed",
                        Some(MembershipStatus::Revoked) => "Revoked",
                        None => "Unknown",
                    };
                    json!({
                        "id": member_id,
                        "status": "skipped",
                        "message": format!("Member is in {} status, not Accepted", status_name)
                    })
                }
            }
            None => {
                failed_count += 1;
                json!({
                    "id": member_id,
                    "status": "error",
                    "message": "Member not found"
                })
            }
        };
        
        results.push(result);
    }
    
    Ok(Json(json!({
        "data": results,
        "object": "list",
        "summary": {
            "total": total_count,
            "confirmed": confirmed_count,
            "failed": failed_count,
            "skipped": total_count - confirmed_count - failed_count
        }
    })))
}

pub struct PublicToken(OrganizationId);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PublicToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();
        // Get access_token
        let access_token: &str = match headers.get_one("Authorization") {
            Some(a) => match a.rsplit("Bearer ").next() {
                Some(split) => split,
                None => err_handler!("No access token provided"),
            },
            None => err_handler!("No access token provided"),
        };
        // Check JWT token is valid and get device and user from it
        let Ok(claims) = auth::decode_api_org(access_token) else {
            err_handler!("Invalid claim")
        };
        // Check if time is between claims.nbf and claims.exp
        let time_now = Utc::now().timestamp();
        if time_now < claims.nbf {
            err_handler!("Token issued in the future");
        }
        if time_now > claims.exp {
            err_handler!("Token expired");
        }
        // Check if claims.iss is domain|claims.scope[0]
        let complete_host = format!("{}|{}", CONFIG.domain_origin(), claims.scope[0]);
        if complete_host != claims.iss {
            err_handler!("Token not issued by this server");
        }

        // Check if claims.sub is org_api_key.uuid
        // Check if claims.client_sub is org_api_key.org_uuid
        let conn = match DbConn::from_request(request).await {
            Outcome::Success(conn) => conn,
            _ => err_handler!("Error getting DB"),
        };
        let Some(org_id) = claims.client_id.strip_prefix("organization.") else {
            err_handler!("Malformed client_id")
        };
        let org_id: OrganizationId = org_id.to_string().into();
        let Some(org_api_key) = OrganizationApiKey::find_by_org_uuid(&org_id, &conn).await else {
            err_handler!("Invalid client_id")
        };
        if org_api_key.org_uuid != claims.client_sub {
            err_handler!("Token not issued for this org");
        }
        if org_api_key.uuid != claims.sub {
            err_handler!("Token not issued for this client");
        }

        Outcome::Success(PublicToken(claims.client_sub))
    }
}
