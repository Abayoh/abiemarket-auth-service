

export const roleMapPermissions: Record<string, string[]> = {
  shopper: [
   'manage:address',
   'request:seller',
   'manage:account'
  ],
  shopperAdmin: [
   'manage:account',
  ],
  seller:[
    'manage:account',
    'manage:product',
    'manage:order',
    'manage:inventory',
    'manage:promotion',
  ]
};

export default roleMapPermissions;


