enum LocalStorageKeyEnum {
  ACCESS_TOKEN = "accessToken",
  REFRESH_TOKEN = "refreshToken",
}

export const removeLocalStorageItem = (key: LocalStorageKeyEnum) => {
  return localStorage.removeItem(key);
};

export const getLocalStorageItem = (key: LocalStorageKeyEnum) => {
  return localStorage.getItem(key);
};

export const setLocalStorageItem = (
  key: LocalStorageKeyEnum,
  value: string,
) => {
  return localStorage.setItem(key, value);
};
