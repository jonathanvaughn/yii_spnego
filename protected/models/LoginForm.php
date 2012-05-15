<?php

/**
 * LoginForm class.
 * LoginForm is the data structure for keeping
 * user login form data. It is used by the 'login' action of 'SiteController'.
 */
class LoginForm extends CFormModel
{
	public $username;
	public $password;
	public $rememberMe;
        public $krbData;
        public $krbKeytab;

	private $_identity;

	/**
	 * Declares the validation rules.
	 * The rules state that username and password are required,
	 * and password needs to be authenticated.
	 */
	public function rules()
	{
		return array(
			// username and password are required
			array('username, password', 'required'),
			// rememberMe needs to be a boolean
			array('rememberMe', 'boolean'),
			// password needs to be authenticated
			array('password', 'authenticate'),
		);
	}

	/**
	 * Declares attribute labels.
	 */
	public function attributeLabels()
	{
		return array(
			'rememberMe'=>'Remember me next time',
		);
	}

	/**
	 * Authenticates the password.
	 * This is the 'authenticate' validator as declared in rules().
	 */
	public function authenticate($attribute,$params)
	{
		if(!$this->hasErrors())
		{
			$this->_identity=new UserIdentity($this->username,$this->password);
			if(!$this->_identity->authenticate())
				$this->addError('password','Incorrect username or password.');
		}
	}
        
        /**
         * Validates the Kerberos credentials 
         */
        public function validateKrb()
        {
                if(!extension_loaded('krb5'))
                {
                    die('KRB5 Extension not installed but validateKrb called anyway!');
                }
                Yii::log('Validating','info','system.web.CController');
                $auth = new KRB5NegotiateAuth($this->krbKeytab);
                
                try {
                    $reply = $auth->doAuthentication(base64_decode($this->krbData));
                }
                catch (Exception $e) 
                {
                    Yii::log('Caught exception '.$e->getMessage(),'info','system.web.CController');
                }
                
                if ($reply)
                {
                    Yii::log('Authenticated as '.$auth->getAuthenticatedUser(),'info','system.web.CController');
                    // Successful authentication
                    $this->_identity=new UserIdentity($auth->getAuthenticatedUser(),'kerberos'); //FIXME: login from Kerberos
                    if (!$this->_identity->authenticate($krb5 = true))
                    {
                                Yii::log('identity: '.$this->_identity->username,'info','system.web.CController');
                                $this->addError('password','Incorrect Kerberos authentication');
                                return 0;
                    }
                    else
                    {
                        return 1;
                    }
                }
                
                
        }

	/**
	 * Logs in the user using the given username and password in the model.
	 * @return boolean whether login is successful
	 */
	public function login()
	{
		if($this->_identity===null)
		{
			$this->_identity=new UserIdentity($this->username,$this->password);
			$this->_identity->authenticate();
		}
		if($this->_identity->errorCode===UserIdentity::ERROR_NONE)
		{
			$duration=$this->rememberMe ? 3600*24*30 : 0; // 30 days
			Yii::app()->user->login($this->_identity,$duration);
			return true;
		}
		else
			return false;
	}
}
