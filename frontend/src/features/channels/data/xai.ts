import { apiRequest } from '@/lib/api-client'

export interface XaiDeviceFlowStartResult {
  session_id: string
  user_code: string
  verification_uri: string
  expires_in: number
  interval: number
}

export interface XaiDeviceFlowPollResult {
  status: string
  message?: string
  access_token?: string
  refresh_token?: string
  token_type?: string
  expires_in?: number
  scope?: string
  /** Full OAuth credential JSON ready to store on the channel. */
  credentials?: string
}

export interface XaiDeviceFlowPollInput {
  session_id: string
}

export async function xaiOAuthStart(headers?: Record<string, string>): Promise<XaiDeviceFlowStartResult> {
  return apiRequest('/admin/xai/oauth/start', {
    method: 'POST',
    body: {},
    headers,
    requireAuth: true,
  })
}

export async function xaiOAuthPoll(
  input: XaiDeviceFlowPollInput,
  headers?: Record<string, string>
): Promise<XaiDeviceFlowPollResult> {
  return apiRequest('/admin/xai/oauth/poll', {
    method: 'POST',
    body: input,
    headers,
    requireAuth: true,
  })
}
