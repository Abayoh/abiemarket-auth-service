export interface VerificationTokenType {
    /** The type of the confirmation token (email or phone). */
    type: 'email' | 'phone';
    /** The value of the confirmation token (email or phone). */
    value: string;
  }
  
  export interface VerificationToken {
    /** The confirmation code that the user must enter to verify their email or phone number. */
    code: string;
  
    /** The expiration date of the confirmation token. */
    expires: Date;
  
    /** The type of the confirmation token (email or phone). */
    verificationType: VerificationTokenType;
    /** The date the document was created. */
    createdAt?: Date;
    /** The date the document was last updated. */
    updatedAt?: Date;
  }