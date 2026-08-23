import * as client from "openid-client";

export type Role = "ADMIN" | "OPERATOR" | "AUDITOR" | "VIEWER";
export type OidcProvider = {
  id:number; name:string; preset:string; issuerUrl:string; clientId:string; encryptedClientSecret:string;
  scopes:string; usernameClaim:string; groupsClaim:string; allowedDomains:string[];
  roleMapping:Partial<Record<Role,string[]>>; defaultRole:Role; jitProvisioning:boolean; enabled:boolean;
};

export const oidcStates=new Map<string,{providerId:number;verifier:string;nonce:string;redirectUri:string;expiresAt:number}>();

export function chooseRole(groups:unknown,mapping:Partial<Record<Role,string[]>>,fallback:Role):Role {
  const memberships=new Set(Array.isArray(groups)?groups.filter((value):value is string=>typeof value==="string"):typeof groups==="string"?[groups]:[]);
  for(const role of ["ADMIN","OPERATOR","AUDITOR","VIEWER"] as Role[]){
    if((mapping[role]??[]).some(group=>memberships.has(group)))return role;
  }
  return fallback;
}

export function allowedEmail(email:string,domains:string[]){
  if(!domains.length)return true;
  const domain=email.split("@")[1]?.toLowerCase();
  return Boolean(domain&&domains.some(item=>item.toLowerCase()===domain));
}

export async function oidcConfiguration(provider:OidcProvider,secret:string){
  return client.discovery(new URL(provider.issuerUrl),provider.clientId,secret);
}

export async function authorizationUrl(provider:OidcProvider,secret:string,redirectUri:string){
  const configuration=await oidcConfiguration(provider,secret);
  const verifier=client.randomPKCECodeVerifier();
  const challenge=await client.calculatePKCECodeChallenge(verifier);
  const state=client.randomState();
  const nonce=client.randomNonce();
  oidcStates.set(state,{providerId:provider.id,verifier,nonce,redirectUri,expiresAt:Date.now()+10*60_000});
  return client.buildAuthorizationUrl(configuration,{redirect_uri:redirectUri,scope:provider.scopes,code_challenge:challenge,code_challenge_method:"S256",state,nonce,prompt:"select_account"});
}

export function consumeState(state:string){
  const value=oidcStates.get(state);oidcStates.delete(state);
  return value&&value.expiresAt>Date.now()?value:null;
}
