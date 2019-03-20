import * as React from "react";
import { Button, ButtonToolbar, Form, Col } from "react-bootstrap";
import ReCAPTCHA from "react-google-recaptcha";

import history from '../../history';
import "./Login.css";
import logo from '../../assets/logo.svg';
import { encryptText, decryptTextWithKey } from '../../utils';

class Login extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      email: '',
      password: '',
      isAuthenticated: false,
      token: "",
      user: {}
    };

    this.recaptchaRef = React.createRef();
  }

  componentDidMount() {
    // Check if recent login is passed and redirect user to X Cloud
    const mnemonic = localStorage.getItem('xMnemonic');
    const user = JSON.parse(localStorage.getItem('xUser'));

    if (user) { 
      this.props.handleKeySaved(user)
      if (user.storeMnemonic === true && mnemonic) {
        // Case of login and mnemonic loaded from server
        history.push('/app')
      } else {
        // Case of login and mnemonic required by user
        history.push('/keyPage');
      }
    }
  }

  componentDidUpdate() {
    if (this.state.isAuthenticated === true && this.state.token && this.state.user) {
      const mnemonic = localStorage.getItem('xMnemonic');
      if (this.state.user.storeMnemonic === true && mnemonic) {
        // Case of login and mnemonic loaded from server
        history.push('/app')
      } else {
        // Case of login and mnemonic loaded from server
        history.push('/KeyPage')
      }
    }
  }

  setHeaders = () => {
    let headers = {
      Authorization: `Bearer ${localStorage.getItem("xToken")}`,
      "content-type": "application/json; charset=utf-8"
    };
    if (!this.state.user.mnemonic) {
      headers = Object.assign(headers, {
        "internxt-mnemonic": localStorage.getItem("xMnemonic")
      });
    }
    return headers;
  }

  validateForm = () => {
    let isValid = true;

    // Email validation
    if (this.state.email.length < 5 || !this.validateEmail(this.state.email)) isValid = false;
    // Pass length check
    if (this.state.password.length < 1) isValid = false;

    return isValid;
  }

  validateEmail = (email) => {
    var re = new RegExp("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?");
    return re.test(String(email).toLowerCase());
  }

  goRegister = () => {
    history.push('/register');
  }

  handleChange = event => {
    this.setState({
      [event.target.id]: event.target.value
    });
  }

  captchaLaunch = event => {
    event.preventDefault();
    this.recaptchaRef.current.execute();
  }

  resolveCaptcha = captchaToken => {
    const headers = this.setHeaders();
    return new Promise((resolve, reject) => {
      fetch('/api/captcha/' + captchaToken, {
        method: 'GET',
        headers
      }).then(response => { resolve(response); })
      .catch(err => { reject(err); });
    });
  }

  handleSubmit = captchaToken => {
    // Captcha resolution
    const captchaPromise = this.resolveCaptcha(captchaToken) 
    captchaPromise.then(response => response.json())
    .then((resolved) => {
      if (resolved.success) {
        const headers = this.setHeaders();
        // Proceed with submit
        fetch("/api/login", {
          method: "post",
          headers,
          body: JSON.stringify({ email: this.state.email, password: encryptText(this.state.password) })
        })
        .then(response => {
            if (response.status === 200) {
              // Manage succesfull login
              response.json().then( (body) => {
                const user = { 
                  userId: body.user.userId,
                  email: this.state.email,  
                  mnemonic: decryptTextWithKey(body.user.mnemonic, this.state.password),
                  root_folder_id: body.user.root_folder_id,
                  storeMnemonic: body.user.storeMnemonic 
                };
                this.props.handleKeySaved(user)
                localStorage.setItem('xToken',body.token);
                if (user.mnemonic && body.user.storeMnemonic === true) localStorage.setItem('xMnemonic', user.mnemonic);
                localStorage.setItem('xUser', JSON.stringify(user));
                this.setState({ 
                  isAuthenticated: true, 
                  token: body.token,
                  user: user
                })
              });
            } else if(response.status === 400) {
              // Manage other cases:
              // username / password do not match, user activation required...
              response.json().then( (body) => {
                alert(body.message);
              });
            } else {
              // Manage user does not exist
              alert("This account doesn't exists");
            }
        })
          .catch(err => {
            console.error("Login error. " + err);
        });
      }
    }).catch((error) => {
      console.error('Captcha validation error: ' + error);
    })
    // After login
    this.recaptchaRef.current.reset();
  }

  render() {
    const isValid = this.validateForm();
    return (
      <div>
        <img src={logo} className="Logo" style={{height: 46 ,width: 46}}/>
        <div id="Login" className="Login">
        <div className="LoginHeader">
          <h2> Welcome to X Cloud</h2>
          <ButtonToolbar>
              <Button size="lg" className="button-on">Sign in</Button>
              <Button size="lg" className="button-off" onClick={this.goRegister}>Create account</Button>
            </ButtonToolbar>
            <h4>Enter your details below</h4>
        </div>
          <Form className="formBlock" onSubmit={this.captchaLaunch}>
            <Form.Row>
              <Form.Group as={Col} controlId="email">
                <Form.Control autoFocus required size="lg" type="email" placeholder="Email" value={this.state.email} onChange={this.handleChange} />
              </Form.Group>
              <Form.Group as={Col} controlId="password">
                <Form.Control required size="lg" type="password" placeholder="Password" value={this.state.password} onChange={this.handleChange} />
              </Form.Group>
            </Form.Row>
            <ReCAPTCHA sitekey="6Lf4_xsUAAAAAAEEhth1iM8LjyUn6gse-z0Y7iEp"
              ref={this.recaptchaRef}
              size="invisible"
              onChange={this.handleSubmit}
            />
            <p id="Terms">By signing in, you are agreeing to our <a href="https://internxt.com/terms">Terms {"&"} Conditions</a> and <a href="https://internxt.com/privacy">Privacy Policy</a></p>
            <Button className="button-submit" disabled={!isValid} size="lg" type="submit" block> Continue </Button>
          </Form> 
        </div>
      </div>
    );
  }
}

export default Login;
