# Gemini Project Documentation

This document provides an overview of the Electron Forge, Vite, and React proof of concept (POC) application.

## Project Overview

This project is a desktop application built with Electron, using Vite as the build tool and React for the user interface. Electron Forge is used to package and distribute the application.

### Key Technologies

*   **Electron:** A framework for building cross-platform desktop applications with web technologies.
*   **Electron Forge:** A complete tool for creating, packaging, and publishing Electron applications.
*   **Vite:** A modern build tool that provides a fast development experience.
*   **React:** A JavaScript library for building user interfaces.

## Project Structure

```
/
├───.gitignore
├───forge.config.js
├───index.html
├───LICENSE
├───package-lock.json
├───package.json
├───README.md
├───vite.main.config.mjs
├───vite.preload.config.mjs
├───vite.renderer.config.mjs
├───yarn.lock
├───.git/...
├───.vite/...
├───node_modules/...
└───src/
    ├───index.css
    ├───main.js
    ├───preload.js
    ├───renderer.jsx
    └───components/
        └───Hello.jsx
```

### File Descriptions

*   **`forge.config.js`**: The main configuration file for Electron Forge. It defines the application's packager settings, makers (for creating installers), and plugins.
*   **`vite.main.config.mjs`**: The Vite configuration file for the main process.
*   **`vite.preload.config.mjs`**: The Vite configuration file for the preload script.
*   **`vite.renderer.config.mjs`**: The Vite configuration file for the renderer process.
*   **`src/main.js`**: The entry point for the Electron main process. It creates the browser window and handles system events.
*   **`src/preload.js`**: A script that runs before the renderer process is loaded. It can be used to expose Node.js APIs to the renderer process in a secure way.
*   **`src/renderer.jsx`**: The entry point for the React application that runs in the renderer process.
*   **`src/components/Hello.jsx`**: A simple React component that displays a "Hello" message.

## How it Works

1.  **Electron Forge** reads the `forge.config.js` file to determine how to build and package the application.
2.  The `@electron-forge/plugin-vite` plugin is used to build the main process, preload script, and renderer process using Vite.
3.  **Vite** uses the respective configuration files (`vite.main.config.mjs`, `vite.preload.config.mjs`, and `vite.renderer.config.mjs`) to build each part of the application.
4.  The **main process** (`src/main.js`) creates a `BrowserWindow`.
5.  The **preload script** (`src/preload.js`) is loaded into the `BrowserWindow`.
6.  The **renderer process** (`src/renderer.jsx`) is loaded into the `BrowserWindow`, and the React application is rendered.

## Future Goals

The goal is to add functionalities to this application, such as:

*   Fetching the number of screens on the laptop.
*   Fetching all connected devices like USBs, cameras, etc.
*   Fetching the processes running on the system at all times.
