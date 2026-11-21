import { Link, useSearchParams } from 'react-router-dom';
import { Card, Notice } from '../components/ui';
import { loginUrl } from '../lib/api';
import { useAuth } from '../lib/auth';

export default function Login() {
  const [params] = useSearchParams();
  const { me, unreachable } = useAuth();
  const failed = params.get('error') === 'oauth_failed';
  return (
    <Card className="mx-auto max-w-xl text-center">
      <p className="eyebrow">Passwordless</p>
      <h1 className="mt-2 font-display text-4xl">Connect with Instagram</h1>
      <p className="mt-3 text-sm text-navy-800/75">You’ll be sent to Instagram’s own login page. MutualX only receives a limited, revocable access token — never your password. Connecting is optional: the Mutuals tool works without it.</p>
      <div className="mt-5 space-y-3">
        {failed && <Notice tone="error">Sign-in didn’t complete. Nothing was connected. Please try again.</Notice>}
        {unreachable && <Notice tone="warn">The MutualX API is not reachable right now.</Notice>}
      </div>
      <div className="mt-6 flex flex-wrap justify-center gap-3">
        {me ? <Link className="btn-primary" to="/account">Go to your account</Link> : <a className="btn-primary" href={loginUrl}>Continue to Instagram</a>}
        <Link className="btn-ghost" to="/">Back to Mutuals</Link>
      </div>
      <p className="mt-5 text-xs text-navy-800/55">Business and Creator accounts only — a limit set by Meta’s API, not by MutualX.</p>
    </Card>
  );
}
