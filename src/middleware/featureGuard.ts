import { Request, Response, NextFunction } from 'express';
import { FeatureKey, isFeatureEnabled }    from '../config/features.js';

export function featureGuard(feature: FeatureKey) {
  return (_req: Request, res: Response, next: NextFunction) => {
    if (!isFeatureEnabled(feature)) {
      return res.status(403).json({
        error:   'Feature not available',
        feature,
        message: 'This feature is currently disabled.',
      });
    }
    next();
  };
}
