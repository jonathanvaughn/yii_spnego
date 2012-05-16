<?php

/**
 * UserIdentity represents the data needed to identity a user.
 * It contains the authentication method that checks if the provided
 * data can identity the user.
 */
class UserIdentity extends CUserIdentity
{
        
        const ERROR_KRB5_KEYTAB = 3; // Something went wrong loading the keytab
        const ERROR_KRB5_AUTH = 4; // Something went wrong while authenticating

        var $name = '';
        
	/**
	 * Authenticates a user.
	 * The example implementation makes sure if the username and password
	 * are both 'demo'.
	 * In practical applications, this should be changed to authenticate
	 * against some persistent user identity storage (e.g. database).
	 * @return boolean whether authentication succeeds.
	 */
	public function authenticate()
	{
            
            $this->errorCode=self::ERROR_NONE;
            
            // Check for WWW-Negotiate authentication, assuming we have the krb5
            // extension
            if ((substr($this->username,0,9) == 'Kerberos:') && (extension_loaded('krb5')))
                {
                // Extract the Negotiate data from the username field
                $data = substr($this->username,9);
                // Check if this is Kerberos data
                if (substr($data,0,3) == 'YII')
                    {
                    // We have Kerberos data, attempt to authenticate using it
                    
                    $auth = new KRB5NegotiateAuth($this->password);
                    
                    if (!$auth)
                        {
                        // Problem with the Keytab
                        $this->errorCode = ERROR_KRB5_KEYTAB;
                        }
                    else 
                        {
                        // Keytab succesfully loaded, try to authenticate
                        $reply = $auth->doAuthentication(base64_decode($this->username));
                        
                        if ($reply)
                            {
                            
                            // Successful authentication
                            $this->errorCode=self::ERROR_NONE;
                            $this->name = $auth->getAuthenticatedUser();
                            }
                        else
                            {
                            // Authentication failed
                            $this->errorCode = ERROR_KRB5_AUTH;
                            }
                        }
                    }
                if ($this->errorCode)
                    {
                    // If the user ends up seeing an error we don't want to fill
                    // the form in with useless data
                    $this->username = '';
                    $this->password = '';
                    }
                }
            else
                {
                    
                // Normal login via form
		$users=array(
			// username => password
			'demo'=>'demo',
			'admin'=>'admin',
		);             
		if(!isset($users[$this->username]))
			$this->errorCode=self::ERROR_USERNAME_INVALID;
		else if($users[$this->username]!==$this->password)
			$this->errorCode=self::ERROR_PASSWORD_INVALID;
		else
                    {
                        $this->name = $this->username;
			$this->errorCode=self::ERROR_NONE;
                    }
                }
                return $this->errorCode;
	}
        
        /**
	 * Returns the unique identifier for the identity.
	 * The default implementation simply returns {@link username}.
	 * This method is required by {@link IUserIdentity}.
	 * @return string the unique identifier for the identity.
	 */
	public function getId()
	{
		return $this->name;
	}

	/**
	 * Returns the display name for the identity.
	 * The default implementation simply returns {@link username}.
	 * This method is required by {@link IUserIdentity}.
	 * @return string the display name for the identity.
	 */
	public function getName()
	{
		return $this->name;
	}
}