import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { Input } from '../ui/input';
import { Label } from '../ui/label';

export interface PassphraseEntry {
  passphrase: string;
  hint?: string;
}

interface ConfigPassphraseDialogProps {
  mode: 'export' | 'import';
  /** The file's hint, shown when importing. */
  hint?: string;
  /** Resolves false for a wrong passphrase, which keeps the dialog open. */
  onSubmit: (entry: PassphraseEntry) => Promise<boolean>;
  onCancel: () => void;
}

const MAX_HINT_LENGTH = 200;

export function ConfigPassphraseDialog({ mode, hint, onSubmit, onCancel }: ConfigPassphraseDialogProps) {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [newHint, setNewHint] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isChecking, setIsChecking] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (isChecking) return;
    if (mode === 'export' && passphrase !== confirmation) {
      setError(t('settings.advanced.passphrase.mismatch'));
      return;
    }
    setIsChecking(true);
    const accepted = await onSubmit({ passphrase, hint: newHint.trim() || undefined });
    setIsChecking(false);
    if (accepted === false) {
      setError(t('settings.advanced.passphrase.wrong'));
    }
  };

  return (
    <Dialog open onOpenChange={(open) => { if (!open && !isChecking) onCancel(); }}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={(event) => void handleSubmit(event)} className="space-y-4">
          <DialogHeader>
            <DialogTitle>
              {mode === 'export'
                ? t('settings.advanced.passphrase.exportTitle')
                : t('settings.advanced.passphrase.importTitle')}
            </DialogTitle>
            <DialogDescription>
              {mode === 'export'
                ? t('settings.advanced.passphrase.exportDesc')
                : t('settings.advanced.passphrase.importDesc')}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2">
            <Label htmlFor="config-passphrase">{t('settings.advanced.passphrase.label')}</Label>
            <Input
              id="config-passphrase"
              type="password"
              autoFocus
              autoComplete="off"
              value={passphrase}
              onChange={(event) => { setPassphrase(event.target.value); setError(null); }}
            />
          </div>

          {mode === 'export' && (
            <div className="space-y-2">
              <Label htmlFor="config-passphrase-confirm">{t('settings.advanced.passphrase.confirm')}</Label>
              <Input
                id="config-passphrase-confirm"
                type="password"
                autoComplete="off"
                value={confirmation}
                onChange={(event) => { setConfirmation(event.target.value); setError(null); }}
              />
            </div>
          )}

          {mode === 'export' && (
            <div className="space-y-2">
              <Label htmlFor="config-passphrase-hint">{t('settings.advanced.passphrase.hintOptional')}</Label>
              <Input
                id="config-passphrase-hint"
                autoComplete="off"
                maxLength={MAX_HINT_LENGTH}
                value={newHint}
                onChange={(event) => { setNewHint(event.target.value); setError(null); }}
              />
              <p className="text-xs text-muted-foreground">{t('settings.advanced.passphrase.hintDesc')}</p>
            </div>
          )}

          {mode === 'import' && hint && (
            <div className="space-y-1">
              <p className="text-sm font-medium">{t('settings.advanced.passphrase.hint')}</p>
              <p className="text-sm text-muted-foreground break-words">{hint}</p>
            </div>
          )}

          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}

          <DialogFooter>
            <Button type="button" variant="outline" disabled={isChecking} onClick={onCancel}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={passphrase.length === 0 || isChecking}>
              {t('settings.advanced.passphrase.continue')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
