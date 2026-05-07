import { isFeatureEnabled } from '../config/features.js';
export function featureGuard(feature) {
    return (_req, res, next) => {
        if (!isFeatureEnabled(feature)) {
            return res.status(403).json({
                error: 'Feature not available',
                feature,
                message: 'This feature is currently disabled.',
            });
        }
        next();
    };
}
//# sourceMappingURL=featureGuard.js.map