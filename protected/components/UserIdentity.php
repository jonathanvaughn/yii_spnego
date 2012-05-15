<?php

/**
 * UserIdentity represents the data needed to identity a user.
 * It contains the authentication method that checks if the provided
 * data can identity the user.
 */
class UserIdentity extends CUserIdentity
{
	/**
	 * Authenticates a user.
	 * The example implementation makes sure if the username and password
	 * are both 'demo'.
	 * In practical applications, this should be changed to authenticate
	 * against some persistent user identity storage (e.g. database).
	 * @return boolean whether authentication succeeds.
	 */
	public function authenticate($krb5=false)
	{
            if ($krb5 = true)
            {
                Yii::log('authenticate() : krb5 = true','info','system.web.CController');
                if(!extension_loaded('krb5'))
                {
                    die('KRB5 Extension not installed but authenticate with krb5=true called anyway!');
                }
                
                // Do some kind of DB lookup here? We're already authenticated, but not set if admin rights or such
                $this->errorCode=self::ERROR_NONE;
                return !$this->errorCode;
            }
            else
            {
                Yii::log('authenticate() : krb5 = false','info','system.web.CController');
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
			$this->errorCode=self::ERROR_NONE;
		return !$this->errorCode;
            }
	}
}