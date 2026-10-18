import { Link, useParams } from 'react-router-dom';
import { Card, ErrorBox, Loading } from '../components/ui';
import type { CveDetail as CveDetailData } from '../types';
import { useApi } from '../util';

export default function CveDetail() {
  const { cve_id = '' } = useParams();
  const { data, error } = useApi<CveDetailData>(cve_id ? `/vulns/${encodeURIComponent(cve_id)}` : null);

  return (
    <>
      <div className="page-head">
        <h1>{cve_id}</h1>
        <Link to="/vulnerabilities">&larr; Back to vulnerabilities</Link>
      </div>
      <Card title="Details">
        <ErrorBox error={error} />
        {!data ? (!error && <Loading />) : (
          <p className="muted">
            CVSS {data.cvss_base != null ? data.cvss_base.toFixed(1) : 'unknown'} · severity {data.severity ?? 'unknown'}
            {data.kev && ' · actively exploited (KEV)'}
          </p>
        )}
      </Card>
    </>
  );
}
