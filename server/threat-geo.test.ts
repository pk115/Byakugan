import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {it,expect} from 'vitest';
process.env.SUPAPULSE_DATA_DIR=mkdtempSync(join(tmpdir(),'byakugan-geo-'));
const {publicIp,locate}=await import('./threat-geo.js');
it('does not geolocate private loopback documentation or invalid addresses',()=>{
 for(const ip of ['127.0.0.1','192.168.1.5','10.1.2.3','::1','::ffff:127.0.0.1','fc00::1','2001:db8::1','192.0.2.1','bad'])expect(publicIp(ip)).toBeNull();
 expect(publicIp('8.8.8.8')).toBe('8.8.8.8');expect(locate('8.8.8.8',null)).toBeNull();
});
