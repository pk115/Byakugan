import {createHash} from "node:crypto";
import {cp,mkdir,readFile,readdir,stat,writeFile} from "node:fs/promises";
import {basename,join,resolve} from "node:path";
import Database from "better-sqlite3";

const dataDir=resolve(process.env.SUPAPULSE_DATA_DIR??"./data"),outputRoot=resolve(process.argv[2]??"./backups");
const stamp=new Date().toISOString().replace(/[:.]/g,"-"),bundle=join(outputRoot,`supapulse-${stamp}`),source=join(dataDir,"supapulse.db"),target=join(bundle,"supapulse.db");
await mkdir(bundle,{recursive:true});
const db=new Database(source,{readonly:true,fileMustExist:true});
try{await db.backup(target)}finally{db.close()}
const reportsSource=join(dataDir,"reports"),reportsTarget=join(bundle,"reports");
try{if((await stat(reportsSource)).isDirectory())await cp(reportsSource,reportsTarget,{recursive:true})}catch{}
async function files(root,relative=""){const result=[];for(const name of await readdir(join(root,relative))){const next=join(relative,name),info=await stat(join(root,next));if(info.isDirectory())result.push(...await files(root,next));else result.push(next.replaceAll("\\","/"))}return result}
const entries=[];for(const name of await files(bundle)){const body=await readFile(join(bundle,name));entries.push({path:name,bytes:body.length,sha256:createHash("sha256").update(body).digest("hex")})}
const manifest={format:"supapulse-backup-v1",createdAt:new Date().toISOString(),sourceDatabase:basename(source),includesMasterKey:false,files:entries};
await writeFile(join(bundle,"manifest.json"),JSON.stringify(manifest,null,2));
const manifestHash=createHash("sha256").update(await readFile(join(bundle,"manifest.json"))).digest("hex");await writeFile(join(bundle,"manifest.sha256"),`${manifestHash}  manifest.json\n`);
console.log(JSON.stringify({ok:true,bundle,files:entries.length,manifestSha256:manifestHash}));
