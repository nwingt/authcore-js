# authcore-js

### Lints and fixes files
``` shell
yarn run lint
```

### Build the package

``` shell
yarn build
```

### Example test
The example shows how the widgets will be liked in simplest layout(i.e. Without any CSS provided in website).

To run the example, build the package and serve the folder as HTTP server, it can be done by using Python one-liner
``` shell
# Python 2.x:
python -m SimpleHTTPServer 3000

# Python 3.x:
python -m http.server 3000
```

Browse `http://0.0.0.0:3000/example` to see the result
