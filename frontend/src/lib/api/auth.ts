import { api } from './client'
import type { TokenResponse, UserProfile } from './types'

/** Real login: the backend validates credentials and assigns roles. */
export async function login(
  username: string,
  password: string,
): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>('/api/v1/auth/login', {
    username,
    password,
  })
  return data
}

/** The authenticated identity, resolved server-side from the token. */
export async function fetchMe(): Promise<UserProfile> {
  const { data } = await api.get<UserProfile>('/api/v1/auth/me')
  return data
}

/** Recorded logout; the client discards the token either way. */
export async function logout(): Promise<void> {
  await api.post('/api/v1/auth/logout')
}
