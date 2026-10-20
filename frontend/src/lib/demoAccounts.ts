/**
 * Predefined demo identities for the login page.
 *
 * These are the *seeded demo users* of the development database
 * (backend/app/seed.py). Selecting one only fills the login form —
 * authentication and authorization still happen entirely in the backend:
 * the credentials are submitted to `POST /api/v1/auth/login`, roles come
 * from the server response, and no client-side choice can grant a role.
 */

export interface DemoAccount {
  username: string
  password: string
  displayName: string
  role: string
  blurb: string
}

export const DEMO_ACCOUNTS: DemoAccount[] = [
  {
    username: 'sarah.chen',
    password: 'SarahHR@2024!',
    displayName: 'Sarah Chen',
    role: 'hr_manager',
    blurb: 'HR manager — can review salary data for employees.',
  },
  {
    username: 'james.wilson',
    password: 'JamesManager@2024!',
    displayName: 'James Wilson',
    role: 'department_manager',
    blurb: 'Department manager — aggregate reporting only.',
  },
  {
    username: 'eve.johnson',
    password: 'EveSupport@2024!',
    displayName: 'Eve Johnson',
    role: 'support_agent',
    blurb: 'Support agent — customer contact data, masked by policy.',
  },
  {
    username: 'mia.torres',
    password: 'MiaIntern@2024!',
    displayName: 'Mia Torres',
    role: 'marketing_intern',
    blurb: 'Marketing intern — salary access must be blocked.',
  },
  {
    username: 'natalie.brooks',
    password: 'NatalieCust@2024!',
    displayName: 'Natalie Brooks',
    role: 'customer',
    blurb: 'Customer — sees only her own orders.',
  },
  {
    username: 'admin',
    password: 'Admin@2024!',
    displayName: 'Platform Admin',
    role: 'admin',
    blurb: 'Administrator — full trail and policy history.',
  },
]
