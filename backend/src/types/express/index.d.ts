import { UserJwtPayload } from "../jwt.types"

declare global {
  namespace Express {
    interface Locals {
      user: UserJwtPayload,
      error: string | null
    }
  }
}
