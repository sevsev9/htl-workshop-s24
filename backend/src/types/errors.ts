export enum ErrorCode {
    USER_NOT_FOUND = "USER_NOT_FOUND",
    VALIDATION_ERROR = "VALIDATION_ERROR",
    PERMISSION_DENIED = "PERMISSION_DENIED",
    ITEM_NOT_FOUND = "ITEM_NOT_FOUND",
    DATABASE_ERROR = "DATABASE_ERROR",
    UNAUTHORIZED = "UNAUTHORIZED",
    FORBIDDEN = "FORBIDDEN",
    BAD_REQUEST = "BAD_REQUEST",
    DUPLICATE_ENTRY = "DUPLICATE_ENTRY",
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR",
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED",
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE",
    TIMEOUT = "TIMEOUT",
    INVALID_PASSWORD = "INVALID_PASSWORD",
    NO_PASSWORD_STORED = "NO_PASSWORD_STORED",
    INVALID_INPUT = "INVALID_INPUT"
}

const errorMap = new Map<ErrorCode, number>([
    [ErrorCode.USER_NOT_FOUND, 404],
    [ErrorCode.VALIDATION_ERROR, 400],
    [ErrorCode.PERMISSION_DENIED, 403],
    [ErrorCode.ITEM_NOT_FOUND, 404],
    [ErrorCode.DATABASE_ERROR, 500],
    [ErrorCode.UNAUTHORIZED, 401],
    [ErrorCode.FORBIDDEN, 403],
    [ErrorCode.BAD_REQUEST, 400],
    [ErrorCode.DUPLICATE_ENTRY, 409],
    [ErrorCode.INTERNAL_SERVER_ERROR, 500],
    [ErrorCode.NOT_IMPLEMENTED, 501],
    [ErrorCode.SERVICE_UNAVAILABLE, 503],
    [ErrorCode.TIMEOUT, 504],
    [ErrorCode.INVALID_PASSWORD, 400],
    [ErrorCode.NO_PASSWORD_STORED, 400],
    [ErrorCode.INVALID_INPUT, 400]
]);

export class ApplicationError extends Error {
    errorCode: ErrorCode;

    constructor(message: string, statusCode: ErrorCode) {
        super(message);
        this.errorCode = statusCode;
        Error.captureStackTrace(this, this.constructor);
    }

    getHttpCode() {
        return errorMap.get(this.errorCode) || 500;
    }
}