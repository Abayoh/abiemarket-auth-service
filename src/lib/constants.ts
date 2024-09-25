export interface ResponseDefault {
  result: any;
  error: any;
  messages: string[];
  success: boolean;
}
export const responseDefault: ResponseDefault = {
  result: null,
  error: null,
  messages: [],
  success: true,
};
