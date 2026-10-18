import { Card, Empty, ErrorBox, Loading } from '../components/ui';
import type { VulnSummary } from '../types';
import { useApi } from '../util';

export default function Vulnerabilities() {
  const { data, error } = useApi<VulnSummary>('/vulns/summary');

  return (
    <>
      <div className="page-head">
        <h1>Vulnerabilities</h1>
      </div>
      <Card title="Vulnerabilities">
        <ErrorBox error={error} />
        {!data ? (!error && <Loading />) : data.confirmed_count + data.potential_count === 0 ? (
          <Empty>No matched vulnerabilities yet.</Empty>
        ) : (
          <p className="muted">
            {data.confirmed_count + data.potential_count} open finding(s), {data.kev_count} actively exploited (KEV).
          </p>
        )}
      </Card>
    </>
  );
}
