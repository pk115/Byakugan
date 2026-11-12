import {BlockList,isIP} from 'node:net';
import {join} from 'node:path';
import {open,type Reader,type CityResponse} from 'maxmind';
import {config} from './config.js';
import {db} from './database.js';
db.exec(`CREATE TABLE IF NOT EXISTS threat_locations(agent_id INTEGER PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,label TEXT NOT NULL,latitude REAL NOT NULL,longitude REAL NOT NULL);`);
const privateRanges=new BlockList();
for(const [ip,prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.168.0.0',16],['192.0.0.0',24],['192.0.2.0',24],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]] as const)privateRanges.addSubnet(ip,prefix,'ipv4');
for(const [ip,prefix] of [['::',128],['::1',128],['fc00::',7],['fe80::',10],['ff00::',8],['2001:db8::',32]] as const)privateRanges.addSubnet(ip,prefix,'ipv6');
export function publicIp(value:string){const ip=value.toLowerCase().startsWith('::ffff:')?value.slice(7):value;const version=isIP(ip);return version&&!privateRanges.check(ip,version===4?'ipv4':'ipv6')?ip:null;}
let reader:Reader<CityResponse>|null=null,attempted=0;
export async function geoReader(){
  if(!reader&&Date.now()-attempted>60000){attempted=Date.now();try{reader=await open<CityResponse>(process.env.SUPAPULSE_GEOIP_PATH||join(config.dataDir,'geoip','city.mmdb'),{watchForUpdates:true,watchForUpdatesNonPersistent:true});}catch{reader=null;}}
  return reader;
}
export function locate(ip:string|null,dbReader:Reader<CityResponse>|null){
  const valid=ip&&publicIp(ip);if(!valid||!dbReader)return null;
  try{const r=dbReader.get(valid),lat=r?.location?.latitude,lon=r?.location?.longitude;
    if(typeof lat!=='number'||typeof lon!=='number'||Math.abs(lat)>90||Math.abs(lon)>180)return null;
    return {latitude:lat,longitude:lon,country:r?.country?.iso_code??'Unknown',city:r?.city?.names?.en??null};
  }catch{return null;}
}
export function threatLocations(){return db.prepare('SELECT agent_id AS agentId,label,latitude,longitude FROM threat_locations ORDER BY agent_id').all();}
