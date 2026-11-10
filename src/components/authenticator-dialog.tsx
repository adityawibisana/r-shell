/**
 * Authenticator Dialog (Tools → Authenticator)
 *
 * Lists TOTP accounts with their live codes, a countdown and click-to-copy,
 * and adds or edits accounts from a pasted base32 secret or `otpauth://` URI.
 * Codes come from the Rust side (`authenticator_codes`); this component only
 * holds a plaintext secret while it is being typed into the form.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import { AlertCircle, ArrowLeft, Copy, KeyRound, Pencil, Plus, Search, Trash2 } from 'lucide-react';
import { notify } from '@/lib/notifications';
import {
  AuthenticatorStorageManager,
  AUTHENTICATOR_CHANGED_EVENT,
  DEFAULT_TOTP_PERIOD,
  MAX_TOTP_PERIOD,
  TOTP_ALGORITHMS,
  TOTP_DIGITS,
  fetchAuthenticatorCodes,
  isValidTotpSecret,
  parseTotpInput,
  type AuthenticatorAccount,
  type AuthenticatorCode,
  type TotpAlgorithm,
} from '@/lib/authenticator-storage';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from './ui/alert-dialog';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { PasswordInput } from './ui/password-input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';

export interface AuthenticatorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface FormState {
  id?: string;
  secret: string;
  name: string;
  issuer: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period: string;
  /** The edited account already has a saved secret. */
  hasSavedSecret: boolean;
}

type FormErrors = Partial<Record<'secret' | 'name' | 'period', boolean>>;

const emptyForm: FormState = {
  secret: '',
  name: '',
  issuer: '',
  algorithm: 'SHA1',
  digits: 6,
  period: String(DEFAULT_TOTP_PERIOD),
  hasSavedSecret: false,
};

function formFromAccount(account: AuthenticatorAccount): FormState {
  return {
    id: account.id,
    secret: '',
    name: account.name,
    issuer: account.issuer ?? '',
    algorithm: account.algorithm,
    digits: account.digits,
    period: String(account.period),
    hasSavedSecret: !!account.secret,
  };
}

/** "123456" → "123 456", "12345678" → "1234 5678". */
function formatCode(code: string): string {
  const half = Math.floor(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

const nowSecs = () => Date.now() / 1000;

export function AuthenticatorDialog({ open, onOpenChange }: AuthenticatorDialogProps) {
  const { t } = useTranslation();
  const [accounts, setAccounts] = useState<AuthenticatorAccount[]>([]);
  const [codes, setCodes] = useState<Map<string, AuthenticatorCode>>(new Map());
  const [now, setNow] = useState(nowSecs);
  const [query, setQuery] = useState('');
  const [form, setForm] = useState<FormState | null>(null);
  const [errors, setErrors] = useState<FormErrors>({});
  const [saving, setSaving] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<AuthenticatorAccount | null>(null);
  const fetching = useRef(false);
  const refetch = useRef(false);
  const accountsRef = useRef<AuthenticatorAccount[]>([]);

  // Re-read the list on open and after every change (also from other windows).
  useEffect(() => {
    if (!open) return;
    const reload = () => setAccounts(AuthenticatorStorageManager.getAccounts());
    reload();
    window.addEventListener(AUTHENTICATOR_CHANGED_EVENT, reload);
    window.addEventListener('storage', reload);
    return () => {
      window.removeEventListener(AUTHENTICATOR_CHANGED_EVENT, reload);
      window.removeEventListener('storage', reload);
    };
  }, [open]);

  // A request made while one is in flight runs once that one lands, with
  // the latest list, so an edit never waits for the next code expiry.
  const refreshCodes = useCallback(async () => {
    if (fetching.current) {
      refetch.current = true;
      return;
    }
    fetching.current = true;
    try {
      do {
        refetch.current = false;
        const list = accountsRef.current;
        try {
          const next = await fetchAuthenticatorCodes(list);
          setCodes(new Map(list.map((account, i) => [account.id, next[i]])));
        } catch (error) {
          console.error('[authenticator] Failed to compute codes:', error);
          const message = error instanceof Error ? error.message : String(error);
          setCodes(new Map(list.map((account) => [
            account.id,
            { code: null, expiresAt: null, error: account.secret ? message : null },
          ])));
        }
      } while (refetch.current);
    } finally {
      fetching.current = false;
    }
  }, []);

  useEffect(() => {
    accountsRef.current = accounts;
  }, [accounts]);

  useEffect(() => {
    if (open) void refreshCodes();
  }, [open, accounts, refreshCodes]);

  // One tick per second drives the countdowns and fetches codes as they expire.
  useEffect(() => {
    if (!open) return;
    const id = window.setInterval(() => setNow(nowSecs()), 1000);
    return () => window.clearInterval(id);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    for (const code of codes.values()) {
      if (code.expiresAt !== null && code.expiresAt <= now) {
        void refreshCodes();
        return;
      }
    }
  }, [open, now, codes, refreshCodes]);

  const visibleAccounts = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return accounts;
    return accounts.filter((a) =>
      a.name.toLowerCase().includes(needle) || (a.issuer ?? '').toLowerCase().includes(needle));
  }, [accounts, query]);

  const copyCode = async (code: string) => {
    try {
      await writeText(code);
      notify.success(t('authenticator.copied'));
    } catch (error) {
      notify.error(t('authenticator.copyFailed'), { description: String(error) });
    }
  };

  const setField = <K extends keyof FormState>(field: K, value: FormState[K]) => {
    setForm((prev) => (prev ? { ...prev, [field]: value } : prev));
    setErrors((prev) => ({ ...prev, [field]: undefined }));
  };

  /** A pasted otpauth:// URI fills in every field it carries. */
  const handleSecretChange = (value: string) => {
    const parsed = /^\s*otpauth:\/\//i.test(value) ? parseTotpInput(value) : null;
    setForm((prev) => {
      if (!prev) return prev;
      if (!parsed) return { ...prev, secret: value };
      return {
        ...prev,
        secret: parsed.secret,
        name: parsed.name ?? prev.name,
        issuer: parsed.issuer ?? prev.issuer,
        algorithm: parsed.algorithm ?? prev.algorithm,
        digits: parsed.digits ?? prev.digits,
        period: parsed.period !== undefined ? String(parsed.period) : prev.period,
      };
    });
    setErrors((prev) => ({ ...prev, secret: undefined, ...(parsed?.name ? { name: undefined } : {}) }));
  };

  const handleSave = async () => {
    if (!form) return;
    const period = Number(form.period);
    const secretTyped = form.secret.trim() !== '';
    const nextErrors: FormErrors = {
      secret: secretTyped ? !isValidTotpSecret(form.secret) : !form.hasSavedSecret,
      name: !form.name.trim(),
      period: !Number.isInteger(period) || period < 1 || period > MAX_TOTP_PERIOD,
    };
    if (Object.values(nextErrors).some(Boolean)) {
      setErrors(nextErrors);
      return;
    }
    setSaving(true);
    try {
      await AuthenticatorStorageManager.saveAccount({
        id: form.id,
        name: form.name,
        issuer: form.issuer,
        secret: form.secret,
        algorithm: form.algorithm,
        digits: form.digits,
        period,
      });
      setForm(null);
    } catch (error) {
      notify.error(t('authenticator.saveFailed'), {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSaving(false);
    }
  };

  const confirmDelete = () => {
    if (pendingDelete) AuthenticatorStorageManager.deleteAccount(pendingDelete.id);
    setPendingDelete(null);
  };

  // Closing resets the view, so the next open starts at the full list.
  const handleOpenChange = (next: boolean) => {
    if (!next) {
      setQuery('');
      setForm(null);
    }
    onOpenChange(next);
  };

  const openForm = (next: FormState) => {
    setErrors({});
    setForm(next);
  };

  return (
    <>
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent className="!inset-0 !m-auto h-fit max-h-[85vh] sm:max-w-lg flex flex-col">
          {form ? (
            <>
              <DialogHeader>
                <DialogTitle>{form.id ? t('authenticator.form.titleEdit') : t('authenticator.form.titleNew')}</DialogTitle>
                <DialogDescription>{t('authenticator.form.description')}</DialogDescription>
              </DialogHeader>
              <form
                className="space-y-4 overflow-y-auto min-h-0 px-0.5"
                onSubmit={(e) => { e.preventDefault(); void handleSave(); }}
              >
                <div className="space-y-1.5">
                  <Label htmlFor="authenticator-secret">{t('authenticator.form.secret')}</Label>
                  <PasswordInput
                    id="authenticator-secret"
                    className="font-mono"
                    autoComplete="off"
                    spellCheck={false}
                    autoFocus
                    value={form.secret}
                    placeholder={form.hasSavedSecret
                      ? t('authenticator.form.secretKeepPlaceholder')
                      : t('authenticator.form.secretPlaceholder')}
                    aria-invalid={errors.secret || undefined}
                    onChange={(e) => handleSecretChange(e.target.value)}
                  />
                  <p className={errors.secret ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'}>
                    {errors.secret
                      ? (form.secret.trim() ? t('authenticator.form.secretInvalid') : t('authenticator.form.secretRequired'))
                      : t('authenticator.form.secretHint')}
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label htmlFor="authenticator-issuer">{t('authenticator.form.issuer')}</Label>
                    <Input
                      id="authenticator-issuer"
                      value={form.issuer}
                      placeholder={t('authenticator.form.issuerPlaceholder')}
                      onChange={(e) => setField('issuer', e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="authenticator-name">{t('authenticator.form.name')}</Label>
                    <Input
                      id="authenticator-name"
                      value={form.name}
                      placeholder={t('authenticator.form.namePlaceholder')}
                      aria-invalid={errors.name || undefined}
                      onChange={(e) => setField('name', e.target.value)}
                    />
                    {errors.name && <p className="text-xs text-destructive">{t('authenticator.form.nameRequired')}</p>}
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div className="space-y-1.5">
                    <Label>{t('authenticator.form.algorithm')}</Label>
                    <Select value={form.algorithm} onValueChange={(v) => setField('algorithm', v as TotpAlgorithm)}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {TOTP_ALGORITHMS.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('authenticator.form.digits')}</Label>
                    <Select value={String(form.digits)} onValueChange={(v) => setField('digits', Number(v))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {TOTP_DIGITS.map((d) => <SelectItem key={d} value={String(d)}>{d}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="authenticator-period">{t('authenticator.form.period')}</Label>
                    <Input
                      id="authenticator-period"
                      type="number"
                      min={1}
                      max={MAX_TOTP_PERIOD}
                      value={form.period}
                      aria-invalid={errors.period || undefined}
                      onChange={(e) => setField('period', e.target.value)}
                    />
                  </div>
                </div>
                {errors.period && (
                  <p className="text-xs text-destructive">{t('authenticator.form.periodInvalid', { max: MAX_TOTP_PERIOD })}</p>
                )}
                <p className="text-xs text-muted-foreground">{t('authenticator.form.advancedHint')}</p>
                <DialogFooter>
                  <Button type="button" variant="outline" onClick={() => setForm(null)}>
                    <ArrowLeft className="mr-2 h-4 w-4" />
                    {t('common.back')}
                  </Button>
                  <Button type="submit" disabled={saving}>{t('common.save')}</Button>
                </DialogFooter>
              </form>
            </>
          ) : (
            <>
              <DialogHeader>
                <DialogTitle>{t('authenticator.title')}</DialogTitle>
                <DialogDescription>{t('authenticator.description')}</DialogDescription>
              </DialogHeader>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    className="pl-8"
                    value={query}
                    placeholder={t('authenticator.searchPlaceholder')}
                    aria-label={t('common.search')}
                    onChange={(e) => setQuery(e.target.value)}
                  />
                </div>
                <Button onClick={() => openForm(emptyForm)}>
                  <Plus className="mr-2 h-4 w-4" />
                  {t('authenticator.add')}
                </Button>
              </div>
              <div className="overflow-y-auto min-h-0 -mx-1 px-1">
                {accounts.length === 0 ? (
                  <div className="flex flex-col items-center gap-2 py-10 text-center text-muted-foreground">
                    <KeyRound className="h-8 w-8" />
                    <p className="font-medium text-foreground">{t('authenticator.emptyTitle')}</p>
                    <p className="text-sm">{t('authenticator.emptyDesc')}</p>
                  </div>
                ) : visibleAccounts.length === 0 ? (
                  <p className="py-8 text-center text-sm text-muted-foreground">{t('authenticator.emptySearch')}</p>
                ) : (
                  <ul className="divide-y rounded-md border">
                    {visibleAccounts.map((account) => (
                      <AccountRow
                        key={account.id}
                        account={account}
                        code={codes.get(account.id)}
                        now={now}
                        onCopy={(code) => void copyCode(code)}
                        onEdit={() => openForm(formFromAccount(account))}
                        onDelete={() => setPendingDelete(account)}
                      />
                    ))}
                  </ul>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog open={pendingDelete !== null} onOpenChange={(o) => { if (!o) setPendingDelete(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('authenticator.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('authenticator.deleteDesc', {
                name: pendingDelete ? [pendingDelete.issuer, pendingDelete.name].filter(Boolean).join(' · ') : '',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDelete}>{t('common.delete')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

interface AccountRowProps {
  account: AuthenticatorAccount;
  code: AuthenticatorCode | undefined;
  now: number;
  onCopy: (code: string) => void;
  onEdit: () => void;
  onDelete: () => void;
}

function AccountRow({ account, code, now, onCopy, onEdit, onDelete }: AccountRowProps) {
  const { t } = useTranslation();
  const remaining = code?.expiresAt != null ? Math.max(0, Math.ceil(code.expiresAt - now)) : null;
  const value = code?.code && remaining !== null && remaining > 0 ? code.code : null;

  return (
    <li className="flex items-center gap-3 px-3 py-2.5">
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{account.issuer || account.name}</p>
        {account.issuer && <p className="truncate text-xs text-muted-foreground">{account.name}</p>}
        {!account.secret ? (
          <p className="mt-1 flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
            <AlertCircle className="h-3.5 w-3.5" />
            {t('authenticator.secretMissing')}
          </p>
        ) : code?.error ? (
          <p className="mt-1 flex items-center gap-1 text-xs text-destructive" title={code.error}>
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            <span className="truncate">{t('authenticator.codeError')}</span>
          </p>
        ) : (
          <button
            type="button"
            className="mt-0.5 font-mono text-2xl tracking-wider tabular-nums text-primary hover:opacity-80 disabled:opacity-50"
            disabled={!value}
            title={t('authenticator.clickToCopy')}
            onClick={() => { if (value) onCopy(value); }}
          >
            {value ? formatCode(value) : '••• •••'}
          </button>
        )}
      </div>
      {value && remaining !== null && (
        <CountdownRing remaining={remaining} period={account.period} />
      )}
      <div className="flex items-center">
        {value && (
          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('common.copy')} title={t('common.copy')} onClick={() => onCopy(value)}>
            <Copy className="h-4 w-4" />
          </Button>
        )}
        <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('common.edit')} title={t('common.edit')} onClick={onEdit}>
          <Pencil className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('common.delete')} title={t('common.delete')} onClick={onDelete}>
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </li>
  );
}

function CountdownRing({ remaining, period }: { remaining: number; period: number }) {
  const { t } = useTranslation();
  const radius = 9;
  const circumference = 2 * Math.PI * radius;
  const fraction = Math.min(1, remaining / period);
  const urgent = remaining <= 5;
  return (
    <div
      className="relative flex h-8 w-8 shrink-0 items-center justify-center"
      title={t('authenticator.expiresIn', { count: remaining })}
      aria-label={t('authenticator.expiresIn', { count: remaining })}
    >
      <svg viewBox="0 0 24 24" className="absolute inset-0 h-8 w-8 -rotate-90">
        <circle cx="12" cy="12" r={radius} fill="none" strokeWidth="2.5" className="stroke-muted" />
        <circle
          cx="12"
          cy="12"
          r={radius}
          fill="none"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - fraction)}
          className={urgent ? 'stroke-destructive' : 'stroke-primary'}
        />
      </svg>
      <span className={`text-[10px] tabular-nums ${urgent ? 'text-destructive' : 'text-muted-foreground'}`}>{remaining}</span>
    </div>
  );
}
