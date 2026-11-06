import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { notify } from '@/lib/notifications';
import { writeText as writeClipboardText } from '@tauri-apps/plugin-clipboard-manager';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Switch } from '../ui/switch';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Separator } from '../ui/separator';
import { Checkbox } from '../ui/checkbox';
import { Monitor, Upload, Download, RefreshCw, Copy, Info } from 'lucide-react';
import {
  exportAllConfig,
  hasExportableSecrets,
  importAllConfig,
  UnreadableSecretError,
  type ImportOptions,
} from '@/lib/config-export-import';
import { ConfigPassphraseDialog, type PassphraseEntry } from './config-passphrase-dialog';
import {
  DEFAULT_UPDATE_CONTEXT,
  isCurrentChannelEligible,
  type UpdateContext,
} from '@/lib/update-channel';
import { englishText, settingMatchesQuery } from './shared';

interface AdvancedSectionProps {
  appVersion: string | null;
  updateContext: UpdateContext | null;
  checkUpdates: boolean;
  updateChannel: string;
  updateProxy: string;
  onChange: (key: 'checkUpdates' | 'updateChannel' | 'updateProxy', value: unknown) => void;
  /** Save the modal, then run the manual update check (Check Now flow). */
  onSaveAndCheckForUpdates: () => void;
  /** Reload appearance/editor state after a config import changed them. */
  onConfigImported: () => void;
  query: string;
}

export function AdvancedSection({
  appVersion,
  updateContext,
  checkUpdates,
  updateChannel,
  updateProxy,
  onChange,
  onSaveAndCheckForUpdates,
  onConfigImported,
  query,
}: AdvancedSectionProps) {
  const { t } = useTranslation();
  const [importMerge, setImportMerge] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  // Off by default on purpose: carrying secrets is a per-export decision.
  const [exportSecrets, setExportSecrets] = useState(false);
  const [passphraseRequest, setPassphraseRequest] = useState<{
    mode: 'export' | 'import';
    hint?: string;
    onSubmit: (entry: PassphraseEntry) => Promise<boolean>;
    onCancel: () => void;
  } | null>(null);

  const currentChannelEligible = isCurrentChannelEligible(updateContext ?? DEFAULT_UPDATE_CONTEXT);
  const homebrewManaged = updateContext?.homebrewManaged ?? false;
  const channelValue =
    updateChannel === 'current' && currentChannelEligible ? 'current' : 'stable';

  const requestExportPassphrase = () =>
    new Promise<PassphraseEntry | null>((resolve) => {
      setPassphraseRequest({
        mode: 'export',
        onSubmit: (entry) => {
          setPassphraseRequest(null);
          resolve(entry);
          return Promise.resolve(true);
        },
        onCancel: () => {
          setPassphraseRequest(null);
          resolve(null);
        },
      });
    });

  // The dialog stays open until a passphrase works, so a typo costs one retype
  // rather than picking the file again.
  const unlockSecrets: NonNullable<ImportOptions['unlockSecrets']> = (hint, attempt) =>
    new Promise<void>((resolve, reject) => {
      setPassphraseRequest({
        mode: 'import',
        hint,
        onSubmit: async ({ passphrase }) => {
          try {
            if (!(await attempt(passphrase))) return false;
            resolve();
          } catch (error) {
            reject(error instanceof Error ? error : new Error(String(error)));
          }
          setPassphraseRequest(null);
          return true;
        },
        onCancel: () => {
          setPassphraseRequest(null);
          resolve();
        },
      });
    });

  const describeError = (error: unknown) => {
    if (error instanceof UnreadableSecretError) {
      return t('settings.advanced.secretUnreadable', { name: error.connectionName });
    }
    return error instanceof Error ? error.message : String(error);
  };

  const handleExportConfig = async () => {
    setIsExporting(true);
    try {
      const withSecrets = exportSecrets && hasExportableSecrets();
      if (exportSecrets && !withSecrets) {
        notify.info(t('settings.advanced.noSecretsToExport'));
      }
      const entry = withSecrets ? await requestExportPassphrase() : undefined;
      if (entry === null) {
        notify.info(t('settings.advanced.exportCancelled'));
        return;
      }
      const saved = await exportAllConfig({
        secretsPassphrase: entry?.passphrase,
        secretsHint: entry?.hint,
      });
      if (saved) {
        notify.success(t('settings.advanced.exportSuccess'));
      } else {
        notify.info(t('settings.advanced.exportCancelled'));
      }
    } catch (error) {
      console.error('[export-config]', error);
      notify.error(t('settings.advanced.exportFailed'), { description: describeError(error) });
    } finally {
      setIsExporting(false);
    }
  };

  const handleImportConfig = async () => {
    setIsImporting(true);
    try {
      const result = await importAllConfig(importMerge, { unlockSecrets });
      if (result) {
        notify.success(t('settings.advanced.importSuccess'), {
          description: t('settings.advanced.importSuccessDesc', {
            connections: result.connections,
            profiles: result.profiles,
          }),
        });
        onConfigImported();
      } else {
        notify.info(t('settings.advanced.importCancelled'));
      }
    } catch (error) {
      console.error('[import-config]', error);
      notify.error(t('settings.advanced.importFailed'), { description: describeError(error) });
    } finally {
      setIsImporting(false);
    }
  };

  // t() is strictly keyed off en.json; the search helper takes dynamic keys,
  // so widen it once at this boundary.
  const tt = t as unknown as (key: string) => string;
  const show = (labelKey: string, ...aliases: string[]) =>
    settingMatchesQuery(query, [tt(labelKey), englishText(labelKey), ...aliases]);

  const showUpdates = show('settings.updates.channel.label', 'update channel proxy check version');
  const showBackup = show('settings.advanced.configBackup', 'export import backup config secret');

  if (!showUpdates && !showBackup) {
    return null;
  }

  return (
    <Card className="gap-4 rounded-lg shadow-none">
      <CardHeader className="px-4 pt-4">
        <CardTitle className="flex items-center gap-2">
          <Monitor className="h-4 w-4" />
          {t('settings.advanced.title')}
        </CardTitle>
        <CardDescription>
          {t('settings.advanced.desc')}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 px-4 last:pb-4">
        {showUpdates && (
          <>
            <Separator />

            {/* Current app version — visible on every platform (issue #166) */}
            <div className="flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <Label>{t('settings.advanced.version')}</Label>
                <p className="text-sm text-muted-foreground font-mono">{appVersion ?? '—'}</p>
              </div>
            </div>

            <Separator />

            {homebrewManaged ? (
              <div className="space-y-2 rounded-lg border border-border bg-muted/50 p-3">
                <p className="text-sm font-medium">
                  {t('settings.updates.homebrewManaged.title')}
                </p>
                <p className="text-sm text-muted-foreground">
                  {t('settings.updates.homebrewManaged.desc')}
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 rounded border border-border bg-background px-2 py-1.5 font-mono text-xs">
                    {t('settings.updates.homebrewManaged.command')}
                  </code>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 w-7 shrink-0 p-0"
                    aria-label={t('settings.updates.homebrewManaged.copyCommand')}
                    onClick={() => {
                      void writeClipboardText(t('settings.updates.homebrewManaged.command'))
                        .then(() => notify.success(t('settings.updates.homebrewManaged.commandCopied')))
                        .catch((err: unknown) => console.warn('clipboard write failed:', err));
                    }}
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <Label>{t('settings.updates.channel.label')}</Label>
                  <Select
                    value={channelValue}
                    onValueChange={(value) => onChange('updateChannel', value)}
                  >
                    <SelectTrigger aria-label={t('settings.updates.channel.label')}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="stable">{t('settings.updates.channel.stable')}</SelectItem>
                      <SelectItem value="current" disabled={!currentChannelEligible}>
                        {t('settings.updates.channel.current')}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-sm text-muted-foreground">
                    {currentChannelEligible
                      ? t('settings.updates.channel.currentHint')
                      : t('settings.updates.channel.currentUnavailable')}
                  </p>
                </div>

                <div className="flex items-center justify-between gap-4">
                  <div className="space-y-0.5">
                    <Label>{t('settings.advanced.checkUpdates')}</Label>
                    <p className="text-sm text-muted-foreground">
                      {t('settings.advanced.checkUpdatesDesc')}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={onSaveAndCheckForUpdates}
                      className="gap-1.5"
                    >
                      <RefreshCw className="h-3.5 w-3.5" />
                      {t('settings.advanced.checkNow')}
                    </Button>
                    <Switch aria-label={t('settings.advanced.checkUpdates')}
                      checked={checkUpdates}
                      onCheckedChange={(checked) => onChange('checkUpdates', checked)}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="update-proxy">{t('settings.advanced.updateProxy')}</Label>
                  <Input
                    id="update-proxy"
                    type="url"
                    placeholder={t('settings.advanced.updateProxyPlaceholder')}
                    value={updateProxy}
                    onChange={(event) => onChange('updateProxy', event.target.value)}
                  />
                  <p className="text-sm text-muted-foreground">
                    {t('settings.advanced.updateProxyDesc')}
                  </p>
                </div>
              </>
            )}
          </>
        )}

        {showBackup && (
          <>
            <Separator />

            {/* Config Backup Section */}
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <Monitor className="h-4 w-4" />
                <Label className="text-base font-medium">{t('settings.advanced.configBackup')}</Label>
              </div>
              <p className="text-sm text-muted-foreground">
                {t('settings.advanced.configBackupDesc')}
              </p>

              {/* Info: exports never carry credentials (issue #162) */}
              <div className="flex items-start gap-2 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <Info className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
                <p className="text-xs text-blue-600 dark:text-blue-400">
                  {t('settings.advanced.passwordWarning')}
                </p>
              </div>

              <div className="flex flex-col gap-3">
                <div className="flex items-center justify-between gap-4 p-3 rounded-lg border border-border bg-card">
                  <div className="space-y-0.5">
                    <p className="text-sm font-medium">{t('settings.advanced.exportConfig')}</p>
                    <p className="text-xs text-muted-foreground">
                      {t('settings.advanced.exportConfigDesc')}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <div className="flex items-center gap-2">
                      <Switch
                        id="export-secrets"
                        aria-label={t('settings.advanced.secretExportHint')}
                        title={t('settings.advanced.secretExportHint')}
                        checked={exportSecrets}
                        onCheckedChange={setExportSecrets}
                      />
                      <label
                        htmlFor="export-secrets"
                        className="text-xs text-muted-foreground cursor-pointer select-none"
                      >
                        {t('settings.advanced.secretToggle')}
                      </label>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleExportConfig}
                      disabled={isExporting || isImporting}
                      className="gap-1.5"
                    >
                      <Download className="h-3.5 w-3.5" />
                      {t('settings.advanced.exportConfig')}
                    </Button>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-4 p-3 rounded-lg border border-border bg-card">
                  <div className="space-y-0.5">
                    <p className="text-sm font-medium">{t('settings.advanced.importConfig')}</p>
                    <p className="text-xs text-muted-foreground">
                      {t('settings.advanced.importConfigDesc')}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <div className="flex items-center gap-2">
                      <Checkbox
                        id="import-merge"
                        checked={importMerge}
                        onCheckedChange={(checked) => setImportMerge(checked === true)}
                      />
                      <label
                        htmlFor="import-merge"
                        className="text-xs text-muted-foreground cursor-pointer select-none"
                      >
                        {t('settings.advanced.mergeOption')}
                      </label>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleImportConfig}
                      disabled={isExporting || isImporting}
                      className="gap-1.5"
                    >
                      <Upload className="h-3.5 w-3.5" />
                      {t('settings.advanced.importConfig')}
                    </Button>
                  </div>
                </div>
              </div>
            </div>

            {passphraseRequest && (
              <ConfigPassphraseDialog
                mode={passphraseRequest.mode}
                hint={passphraseRequest.hint}
                onSubmit={passphraseRequest.onSubmit}
                onCancel={passphraseRequest.onCancel}
              />
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
