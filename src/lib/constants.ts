export interface ResponseDefault {
  result: any;
  error: any;
  message: string;
  success: boolean;
}
export const responseDefault: ResponseDefault = {
  result: null,
  error: null,
  message: "",
  success: true,
};
