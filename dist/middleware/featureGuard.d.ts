import { Request, Response, NextFunction } from 'express';
import { FeatureKey } from '../config/features.js';
export declare function featureGuard(feature: FeatureKey): (_req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>> | undefined;
