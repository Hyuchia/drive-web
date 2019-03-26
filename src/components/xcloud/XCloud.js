import * as React from "react";
import { Link } from 'react-router-dom';
import { Alert } from 'react-bootstrap';
import $ from 'jquery';
import _ from 'lodash';
import fileDownload from 'js-file-download';
import update from 'immutability-helper';
import Popup from "reactjs-popup";

import FileCommander from './FileCommander';
import history from '../../history';
import "../../App.css";
import NavigationBar from "../navigationBar/NavigationBar";
import { uploadFile, downloadFile } from '../../utils'
import { resolve } from "dns";
import { rejects } from "assert";

class XCloud extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      email: '',
      isAuthorized: false,
      isInitialized: false,
      isActivated: null,
      token: "",
      chooserModalOpen: false,
      rateLimitModal: false,
      currentFolderId: null,
      currentFolderBucket: null,
      currentCommanderItems: [],
      namePath: [],
      selectedItems: [],
      sortFunction: null
    };
  }

  componentDidMount = () => {
    // When user is not signed in, redirect to login
    if (!this.props.user || !this.props.isAuthenticated) {
      history.push('/login');
    } else {
      this.isUserActivated(this.props.user.email).then(data => {
        // If user is signed in but is not activated set property isActivated to false
        const isActivated = data.activated
        if (isActivated) {
          if (!this.props.user.root_folder_id) {
            // Initialize user in case that is not done yet
            this.userInitialization().then((resultId) => {
              this.getFolderContent(resultId);
            }).catch((error) => {
              const errorMsg = error ? error : '';
              alert('User initialization error ' + errorMsg);
              history.push('/login');
            })
          } else { this.getFolderContent(this.props.user.root_folder_id); }

          this.setState({ isActivated, isInitialized: true });
        }
      }).catch(error => {
        console.log('Error getting user activation status: ' + error)
      })
    }
  }

  setHeaders = () => {
    let headers = {
      Authorization: `Bearer ${localStorage.getItem("xToken")}`,
      "content-type": "application/json; charset=utf-8",
      "internxt-mnemonic": localStorage.getItem("xMnemonic")
    };
    return headers;
  }

  userInitialization = () => {
    const headers = this.setHeaders();
    return new Promise((resolve, reject) => {
      fetch('/api/initialize', {
        method: "post",
        headers,
        body: JSON.stringify({
          email: this.props.user.email,
          mnemonic: localStorage.getItem("xMnemonic")
        })
      }).then(response => {
        if (response.status === 200) {
          // Successfull intialization
          this.setState({ isInitialized: true });
          // Set user with new root folder id
          response.json().then((body) => {
            let updatedUser = this.props.user;
            updatedUser.root_folder_id = body.user.root_folder_id;
            this.props.handleKeySaved(updatedUser);
            resolve(body.user.root_folder_id);
          })
        } else { reject(null); }
      }).catch(error => { reject(error); });
    });
  }

  isUserActivated = (email) => {
    let headers = this.setHeaders();
    headers = Object.assign(headers, { "xEmail": email });

    return fetch('/api/user/isactivated', {
      method: 'get',
      headers
    }).then(response => response.json())
      .catch(error => error)
  }

  setSortFunction = (newSortFunc) => {
    // Set new sort function on state and call getFolderContent for refresh files list
    this.setState({ sortFunction: newSortFunc });
    this.getFolderContent(this.state.currentFolderId);
  }

  createFolder = () => {
    const folderName = prompt("Please enter folder name");
    const headers = this.setHeaders();
    if (folderName != null) {
      fetch(`/api/storage/folder`, {
        method: "post",
        headers,
        body: JSON.stringify({
          parentFolderId: this.state.currentFolderId,
          folderName
        })
      }).then(() => {
        this.getFolderContent(this.state.currentFolderId, false);
      });
    }
  }

  openFolder = (e) => {
    this.getFolderContent(e);
  }

  getFolderContent = (rootId, updateNamePath = true) => {
    const headers = this.setHeaders();
    fetch(`/api/storage/folder/${rootId}`, {
      method: "get",
      headers
    })
      .then(response => response.json())
      .then(data => {
        this.deselectAll();
        // Set new items list and apply sort function if is set
        let newCommanderFolders = _.map(data.children, o => _.extend({ type: "Folder" }, o))
        let newCommanderFiles = data.files;
        if (this.state.sortFunction) {
          newCommanderFolders.sort(this.state.sortFunction);
          newCommanderFiles.sort(this.state.sortFunction);
        }
        this.setState({
          currentCommanderItems: _.concat(newCommanderFolders, newCommanderFiles),
          currentFolderId: data.id,
          currentFolderBucket: data.bucket,
          selectedItems: []
        });
        if (updateNamePath) {
          // Only push path if it is not the same as actual path
          if (this.state.namePath.length === 0 || (this.state.namePath[this.state.namePath.length - 1].id !== data.id)) {
            const folderName = data.name.includes("root") ? "All Files" : data.name;
            this.setState({
              namePath: this.pushNamePath({
                name: folderName,
                id: data.id,
                bucket: data.bucket
              }),
              isAuthorized: true
            });
          }
        }
      });
  }

  downloadFile = (id) => {
    const headers = this.setHeaders();
    fetch(`/api/storage/file/${id}`, {
      method: "get",
      headers
    }).then(async (data) => {
      if (data.status === 402) {
        this.setState({ rateLimitModal: true })
        return;
      }
      const blob = await data.blob()
      const name = data.headers.get('x-file-name')
      fileDownload(blob, name)
    })
  }

  localDownloadFile = (id) => {
    downloadFile(this.props.user, this.state.currentFolderBucket, id)
      .then((result) => {
        console.log('Succesfully downloaded file: ' + res.fileName);
        fileDownload(res.blob, res.fileName)
      }).catch((error) => {
        console.error(error);
      })
  }

  openUploadFile = () => {
    $("input#uploadFile").trigger("click");
  }

  uploadFile = (e) => {
    let test = true;
    if (test) {
      const folderName = this.state.namePath.length > 1 ? this.state.namePath[this.state.namePath.length - 1].name : "Root folder";
      const folder = {
        name: folderName,
        bucket: this.state.currentFolderBucket
      }
      uploadFile(this.props.user, folder, e.target.files[0])
      .then((result) => {
        console.log('Successfully uploaded file: ' + result.filename);
      }).catch((error) => {
        console.error(error);
      });
    } else {
      const data = new FormData();
      let headers = this.setHeaders();
      delete headers['content-type'];
      data.append('xfile', e.target.files[0]);
      fetch(`/api/storage/folder/${this.state.currentFolderId}/upload`, {
        method: "post",
        headers,
        body: data
      }).then((response) => {
        if (response.status === 402) {
          this.setState({ rateLimitModal: true })
          return;
        }
        this.getFolderContent(this.state.currentFolderId);
      })
    }
  }

  uploadDroppedFile = (e) => {
    console.log("UPLOAD DROPPED");
    console.log(e);
    const data = new FormData();
    let headers = this.setHeaders();
    delete headers['content-type'];
    data.append('xfile', e[0]);
    fetch(`/api/storage/folder/${this.state.currentFolderId}/upload`, {
      method: "post",
      headers,
      body: data
    }).then((response) => {
      if (response.status === 402) {
        this.setState({ rateLimitModal: true })
        return;
      }
      this.getFolderContent(this.state.currentFolderId);
    })
  }

  deleteItems = () => {
    const selectedItems = this.state.selectedItems;
    const bucket = _.last(this.state.namePath).bucket;
    const headers = this.setHeaders();
    const fetchOptions = {
      method: "DELETE",
      headers
    };
    if (selectedItems.length === 0) return;
    const deletionRequests = _.map(selectedItems, (v, i) => {
      const url =
        v.type === "Folder"
          ? `/api/storage/folder/${v.id}`
          : `/api/storage/bucket/${bucket}/file/${v.bucket}`;
      return fetch(url, fetchOptions);
    });
    Promise.all(deletionRequests)
      .then(result => {
        setTimeout(() => {
          this.getFolderContent(this.state.currentFolderId, false);
        }, 100);
      })
      .catch(err => {
        throw new Error(err);
      });
  }

  selectCommanderItem = (i, e) => {
    const selectedItems = this.state.selectedItems;
    const id = e.target.getAttribute("data-id");
    const type = e.target.getAttribute("data-type");
    const bucket = e.target.getAttribute("data-bucket");
    if (_.some(selectedItems, { id })) {
      const indexOf = _.findIndex(selectedItems, o => o.id === id);
      this.setState({
        selectedItems: update(selectedItems, { $splice: [[indexOf, 1]] })
      });
    } else {
      this.setState({
        selectedItems: update(selectedItems, { $push: [{ type, id, bucket }] })
      });
    }
    e.target.classList.toggle("selected");
  }

  deselectAll() {
    const el = document.getElementsByClassName("FileCommanderItem");
    for (let e of el) {
      e.classList.remove("selected");
    }
  }

  folderTraverseUp() {
    this.setState(this.popNamePath(), () => {
      this.getFolderContent(_.last(this.state.namePath).id, false);
    });
  }

  pushNamePath(path) {
    return update(this.state.namePath, { $push: [path] });
  }

  popNamePath() {
    return (previousState, currentProps) => {
      return {
        ...previousState,
        namePath: _.dropRight(previousState.namePath)
      };
    };
  }

  openChooserModal() {
    this.setState({ chooserModalOpen: true })
  }

  closeModal = () => {
    this.setState({ chooserModalOpen: false })
  }

  closeRateLimitModal = () => {
    this.setState({ rateLimitModal: false })
  }

  render() {
    // Check authentication
    if (this.props.isAuthenticated && this.state.isActivated && this.state.isInitialized) {
      return (
        <div className="App">
          <NavigationBar
            showFileButtons={true}
            showSettingsButton={true}
            createFolder={this.createFolder}
            uploadFile={this.openUploadFile}
            uploadHandler={this.uploadFile}
            deleteItems={this.deleteItems}
            style
          />
          <FileCommander
            //   folderTree={this.state.folderTree}
            currentCommanderItems={this.state.currentCommanderItems}
            openFolder={this.openFolder}
            downloadFile={this.localDownloadFile}
            selectCommanderItem={this.selectCommanderItem}
            namePath={this.state.namePath}
            handleFolderTraverseUp={this.folderTraverseUp.bind(this)}
            uploadDroppedFile={this.uploadDroppedFile}
            setSortFunction={this.setSortFunction}
          />
          <Popup open={this.state.chooserModalOpen} closeOnDocumentClick onClose={this.closeModal} >
            <div>
              <a href={'xcloud://' + this.state.token + '://' + JSON.stringify(this.props.user)}>Open mobile app</a>
              <a onClick={this.closeModal}>Use web app</a>
            </div>
          </Popup>
          <Popup open={this.state.rateLimitModal} closeOnDocumentClick onClose={this.closeRateLimitModal} className="popup--full-screen">
            <div className="popup--full-screen__content">
              <div className="popup--full-screen__close-button-wrapper">
                <div className="close-button" onClick={this.closeRateLimitModal}>
                  X
                  </div>
              </div>
              <div className="message-wrapper">
                <h1> You have run out of storage space! </h1>
                <h2>Get more storage space by upgrading your storage plan on your settings page.</h2>
              </div>
              <div className="buttons-wrapper">
                <div className="default-button button-primary" onClick={this.goToSettings}>
                  Take me there
                </div>
              </div>
            </div>
          </Popup>
        </div>
      );
    } else {
      // Cases of access error
      // Not authenticated
      if (!this.props.isAuthenticated) {
        return (
          <div className="App">
            <h2>Please <Link to='/login'>login</Link> into your X Cloud account</h2>
          </div>
        )
      }
      // User not activated
      if (this.state.isActivated === false) {
        return (
          <div className="App">
            <Alert variant="danger">
              <h3>Your account needs to be activated!</h3>
              <p> Search your mail inbox for activation mail and follow its instructions </p>
            </Alert>
          </div>
        )
      }
      // If is waiting for async method return blank page
      return (<div></div>)
    }
  }
}

export default XCloud;
