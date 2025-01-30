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

export class ApplicationError extends Error {
    errorCode: ErrorCode;

    constructor(message: string, statusCode: ErrorCode) {
        super(message);
        this.errorCode = statusCode;
        Error.captureStackTrace(this, this.constructor);
    }
}