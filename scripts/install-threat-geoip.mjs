// Explicit maintenance command; never contacts a provider during IP lookups.
import {mkdir,rename,rm} from 'node:fs/promises';
import {createWriteStream} from 'node:fs';
import {Readable,Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {createGunzip} from 'node:zlib';
import {createHash} from 'node:crypto';
import {resolve,join} from 'node:path';
import {open} from 'maxmind';
const month=process.argv[2];
if(!/^\d{4}-(0[1-9]|1[0-2])$/.test(month??''))throw new Error('Usage: node scripts/install-threat-geoip.mjs YYYY-MM [data-directory]');
const dir=resolve(process.argv[3]||process.env.SUPAPULSE_DATA_DIR||'data','geoip');
await mkdir(dir,{recursive:true});const temp=join(dir,`city-${process.pid}.tmp`),target=join(dir,'city.mmdb');
try{
 const response=await fetch(`https://download.db-ip.com/free/dbip-city-lite-${month}.mmdb.gz`,{redirect:'error',signal:AbortSignal.timeout(300000)});
 if(!response.ok||!response.body)throw new Error(`Download failed: ${response.status}`);
 let bytes=0;const hash=createHash('sha256');
 await pipeline(Readable.fromWeb(response.body),createGunzip(),new Transform({transform(chunk,_encoding,cb){bytes+=chunk.length;if(bytes>400_000_000)return cb(new Error('Database exceeds size limit'));hash.update(chunk);cb(null,chunk);}}),createWriteStream(temp,{flags:'wx'}));
 const reader=await open(temp);if(!reader.metadata.databaseType)throw new Error('Invalid MMDB');
 await rename(temp,target);console.log(JSON.stringify({file:target,bytes,sha256:hash.digest('hex'),source:`DB-IP City Lite ${month}`,license:'CC BY 4.0 https://db-ip.com/db/download/ip-to-city-lite'}));
}catch(error){await rm(temp,{force:true});throw error;}
