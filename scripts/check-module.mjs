import fs from 'node:fs';
import assert from 'node:assert/strict';
const m=JSON.parse(fs.readFileSync('module.json','utf8'));
const specs=m.specifications.map(p=>fs.readFileSync(p,'utf8')).join('\n');
for(const [id,refs] of Object.entries(m.scenario_tests)){
  assert(specs.includes(`| ${id} |`),`Missing scenario ${id}`);
  for(const ref of refs){const [file,name]=ref.split('#');assert(fs.readFileSync(file,'utf8').includes(`func ${name}(t *testing.T)`),`Missing ${ref}`)}
}
console.log(`PASS: ${Object.keys(m.scenario_tests).length} storage scenarios`);
