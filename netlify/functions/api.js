const serverless = require('serverless-http');
const app = require('../../server.js');

const handler = serverless(app, {
  binary: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/pdf', 'image/*', 'application/octet-stream']
});

exports.handler = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;
  // /.netlify/functions/api/xyz  ->  /api/xyz   (original /api/xyz paths stay as they are)
  if (event.path.startsWith('/.netlify/functions/api')) {
    event.path = '/api' + event.path.slice('/.netlify/functions/api'.length);
  }
  return handler(event, context);
};
