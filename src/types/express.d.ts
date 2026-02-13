import { UserRole, RoleLayer } from './roles';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        organizationId: string;
        email: string;
        displayName: string;
        roles: UserRole[];
        layers: RoleLayer[];
        sessionId: string;
        tokenId: string;
      };
      requestId?: string;
    }
  }
}
