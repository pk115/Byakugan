// Keep ownership during the same active problem; a higher severity needs fresh attention.
export const activeFindingStatusSql = `CASE WHEN compliance_findings.status='ACKNOWLEDGED'
  AND (CASE compliance_findings.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END)
   >= (CASE excluded.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END)
  THEN 'ACKNOWLEDGED' ELSE 'OPEN' END`;
