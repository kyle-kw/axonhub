import { useState, useCallback, useRef, useEffect } from 'react';
import { toast } from 'sonner';
import { useTranslation } from 'react-i18next';
import {
  xaiOAuthStart,
  xaiOAuthPoll,
  XaiDeviceFlowStartResult,
  XaiDeviceFlowPollResult,
} from '../data/xai';

export interface UseXaiDeviceFlowOptions {
  /**
   * Callback when OAuth credentials are successfully obtained.
   * Receives the full credentials JSON string for channel storage.
   */
  onSuccess?: (credentials: string) => void;
}

export interface UseXaiDeviceFlowState {
  userCode: string | null;
  verificationUri: string | null;
  sessionId: string | null;
  expiresAt: number | null;
  interval: number;
  isPolling: boolean;
  error: string | null;
  isComplete: boolean;
}

export interface UseXaiDeviceFlowActions {
  start: () => Promise<void>;
  reset: () => void;
}

/**
 * Manages xAI OAuth device flow (RFC 8628 against auth.x.ai).
 * On success, delivers durable OAuth credentials JSON including access_token and refresh_token.
 */
export function useXaiDeviceFlow(
  options: UseXaiDeviceFlowOptions = {}
): UseXaiDeviceFlowState & UseXaiDeviceFlowActions {
  const { onSuccess } = options;
  const { t } = useTranslation();

  const [userCode, setUserCode] = useState<string | null>(null);
  const [verificationUri, setVerificationUri] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [interval, setInterval] = useState(5);
  const [isPolling, setIsPolling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isComplete, setIsComplete] = useState(false);

  const pollingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const currentIntervalRef = useRef<number>(5);
  const onSuccessRef = useRef(onSuccess);

  useEffect(() => {
    return () => {
      if (pollingTimeoutRef.current) {
        clearTimeout(pollingTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    onSuccessRef.current = onSuccess;
  }, [onSuccess]);

  const poll = useCallback(
    async (sid: string, expiry: number) => {
      if (Date.now() >= expiry) {
        setIsPolling(false);
        setError(t('channels.dialogs.oauth.errors.deviceFlowExpired'));
        return;
      }

      try {
        const result: XaiDeviceFlowPollResult = await xaiOAuthPoll({ session_id: sid });

        if (result.status === 'complete' && (result.credentials || result.access_token)) {
          setIsPolling(false);
          setIsComplete(true);

          const credentials =
            result.credentials ||
            JSON.stringify({
              access_token: result.access_token,
              refresh_token: result.refresh_token || '',
              token_type: result.token_type || 'bearer',
              expires_at: result.expires_in
                ? new Date(Date.now() + result.expires_in * 1000).toISOString()
                : undefined,
            });

          if (onSuccessRef.current) {
            onSuccessRef.current(credentials);
          }

          toast.success(t('channels.dialogs.oauth.messages.credentialsImported'));
        } else if (result.status === 'pending') {
          pollingTimeoutRef.current = window.setTimeout(() => {
            poll(sid, expiry);
          }, currentIntervalRef.current * 1000);
        } else if (result.status === 'slow_down') {
          const newInterval = currentIntervalRef.current * 2;
          currentIntervalRef.current = newInterval;
          setInterval(newInterval);

          pollingTimeoutRef.current = window.setTimeout(() => {
            poll(sid, expiry);
          }, newInterval * 1000);
        } else {
          setIsPolling(false);
          setError(result.message || result.status || t('common.error'));
        }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        setIsPolling(false);
        setError(errorMessage);
      }
    },
    [t]
  );

  const start = useCallback(async () => {
    if (pollingTimeoutRef.current) {
      clearTimeout(pollingTimeoutRef.current);
      pollingTimeoutRef.current = null;
    }

    setIsPolling(true);
    setError(null);

    try {
      const result: XaiDeviceFlowStartResult = await xaiOAuthStart();

      setUserCode(result.user_code);
      setVerificationUri(result.verification_uri);
      setSessionId(result.session_id);
      const expiry = Date.now() + result.expires_in * 1000;
      setExpiresAt(expiry);
      setInterval(result.interval);
      currentIntervalRef.current = result.interval || 5;

      poll(result.session_id, expiry);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setError(errorMessage);
      setIsPolling(false);
    }
  }, [poll]);

  const reset = useCallback(() => {
    if (pollingTimeoutRef.current) {
      clearTimeout(pollingTimeoutRef.current);
      pollingTimeoutRef.current = null;
    }
    setUserCode(null);
    setVerificationUri(null);
    setSessionId(null);
    setExpiresAt(null);
    setInterval(5);
    currentIntervalRef.current = 5;
    setIsPolling(false);
    setError(null);
    setIsComplete(false);
  }, []);

  return {
    userCode,
    verificationUri,
    sessionId,
    expiresAt,
    interval,
    isPolling,
    error,
    isComplete,
    start,
    reset,
  };
}
