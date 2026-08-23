import {createHash} from "node:crypto";
import {copyFile,cp,mkdir,readFile,rename,rm,stat} from "node:fs/promises";
import {join,resolve} from "node:path";
import Database from "better-sqlite3";

const bundle=resolve(process.argv[2]??"");if(!process.argv[2])throw new Error("Usage: node scripts/restore.mjs /backup/supapulse-TIMESTAMP");
const dataDir=resolve(process.env.SUPAPULSE_DATA_DIR??"./data"),manifestPath=join(bundle,"manifest.json"),manifest=JSON.parse(await readFile(manifestPath,"utf8"));
if(manifest.format!=="supapulse-backup-v1"||!Array.isArray(manifest.files))throw new Error("Unsupported backup manifest");
for(const file of manifest.files){const absolute=resolve(bundle,file.path);if(!absolute.startsWith(bundle+"\\")&&!absolute.startsWith(bundle+"/"))throw new Error("Unsafe backup path");const body=await readFile(absolute),hash=createHash("sha256").update(body).digest("hex");if(hash!==file.sha256||body.length!==file.bytes)throw new Error(`Integrity check failed: ${file.path}`)}
const restoredDb=join(bundle,"supapulse.db"),check=new Database(restoredDb,{readonly:true,fileMustExist:true});try{const result=check.pragma("integrity_check")?.[0];if(!result||Object.values(result)[0]!=="ok")throw new Error("SQLite integrity_check failed")}finally{check.close()}
await mkdir(dataDir,{recursive:true});const current=join(dataDir,"supapulse.db"),safety=join(dataDir,`supapulse.db.pre-restore-${new Date().toISOString().replace(/[:.]/g,"-")}`);let safetyCreated=false;try{if((await stat(current)).isFile()){await copyFile(current,safety);safetyCreated=true}}catch{}
const staged=join(dataDir,"supapulse.db.restore-stage");await copyFile(restoredDb,staged);await rename(staged,current);await rm(`${current}-wal`,{force:true});await rm(`${current}-shm`,{force:true});
try{await rm(join(dataDir,"reports"),{recursive:true,force:true});await cp(join(bundle,"reports"),join(dataDir,"reports"),{recursive:true})}catch{}
console.log(JSON.stringify({ok:true,restoredFrom:bundle,database:current,safetyCopy:safetyCreated?safety:null,masterKeyRestored:false}));
