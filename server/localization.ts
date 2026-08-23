import {db} from "./database.js";

export type SystemLocale="en-US"|"th-TH";
export function systemRegional(){const get=(key:string,fallback:string)=>(db.prepare("SELECT value FROM app_settings WHERE key=?").get(key) as {value?:string}|undefined)?.value??fallback;const configured=get("system_locale","th-TH");return{locale:(configured==="th-TH"?"th-TH":"en-US") as SystemLocale,timezone:get("application_timezone","Asia/Bangkok")}}
export function systemText<T>(english:T,thai:T):T{return systemRegional().locale==="th-TH"?thai:english}
