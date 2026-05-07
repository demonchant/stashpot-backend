import { Request, Response, NextFunction } from 'express';
export interface AuthRequest extends Request {
    user?: {
        id: string;
        wallet: string;
    };
}
export declare function verifyJwt(req: AuthRequest, res: Response, next: NextFunction): Response<any, Record<string, any>> | undefined;
export declare function issueJwt(id: string, wallet: string): string;
/** Generate a nonce for wallet signing */
export declare function generateNonce(wallet: string): Promise<string>;
/** Verify wallet signature against stored nonce */
export declare function verifySignature(wallet: string, signature: string, nonce: string): Promise<boolean>;
