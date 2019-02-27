import _ from 'lodash';
import React, { Component } from 'react';
import { Switch, Route } from 'react-router-dom';

import KeyPage from './KeyPage';
import './App.css';
import Login from './Login';
import Register from './Register';
import XCloud from './XCloud';
import Activation from './Activation';
import NotFound from './NotFound';
import Maintenance from './Maintenance';
import Plans from './components/Plans';
import PayMethods from './components/PayMethods';

import history from './history';
import {StripeProvider} from 'react-stripe-elements';
import Settings from './components/Settings';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      token: "",
      user: {},
      isAuthenticated: false
    }
  }

  // Method for set user and notice login
  handleKeySaved = (user) => {
    this.setState({
      isAuthenticated: true,
      user
    });
  }

  render() {
    return (
      <div>
        <Switch>
          <Route exact path='/register' render={ (props) => <Register {...props}  
            isAuthenticated={this.state.isAuthenticated} /> 
          }/>
          <Route exact path='/login' render={ (props) => <Login {...props}  
            isAuthenticated={this.state.isAuthenticated} 
            handleKeySaved={this.handleKeySaved}/> 
          }/>
          <Route path='/activations/:token' render={ (props) => <Activation {...props} /> }/>
          <Route path='/settings' render={ (props) => <Settings /> }/> 
          <Route exact path='/keyPage' render={ (props) => <KeyPage {...props}
            isAuthenticated={this.state.isAuthenticated}
            user={this.state.user} 
            handleKeySaved={this.handleKeySaved}/> 
          }/>
          <Route exact path='/app' render={ (props) => <XCloud {...props} 
            isAuthenticated={this.state.isAuthenticated} 
            user={this.state.user}
            isActivated={this.state.isActivated}
            handleKeySaved={this.handleKeySaved}/>
          }/>
          <Route exact path='/'>
            <Redirect to="/register"/>
          </Route>
          <Route component={ NotFound } />
        </Switch>
      </div>
    )
  }
}

export default App;
