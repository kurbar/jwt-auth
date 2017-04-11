<?php

namespace Tymon\JWTAuth\Providers;

use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Claims\Factory;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;
use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\JWTAuthFilter;
use Tymon\JWTAuth\JWTManager;
use Tymon\JWTAuth\PayloadFactory;
use Tymon\JWTAuth\Validators\PayloadValidator;

class JWTAuthServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Boot the service provider.
     */
    public function boot()
    {
        $this->package('tymon/jwt-auth', 'jwt', __DIR__.'/../');

        $this->bootBindings();

        // register the command
        $this->commands('tymon.jwt.generate');

        // register the filter
        $this->app['router']->filter('jwt-auth', 'tymon.jwt.filter');
    }

    /**
     * Bind some Interfaces and implementations
     */
    public function bootBindings()
    {
        $this->app['Tymon\JWTAuth\JWTAuth'] = function ($app) {
            return $app['tymon.jwt.auth'];
        };

        $this->app['Tymon\JWTAuth\Providers\User\UserInterface'] = function ($app) {
            return $app['tymon.jwt.provider.user'];
        };

        $this->app['Tymon\JWTAuth\Providers\JWT\JWTInterface'] = function ($app) {
            return $app['tymon.jwt.provider.jwt'];
        };

        $this->app['Tymon\JWTAuth\Providers\Auth\AuthInterface'] = function ($app) {
            return $app['tymon.jwt.provider.auth'];
        };

        $this->app['Tymon\JWTAuth\Providers\Storage\StorageInterface'] = function ($app) {
            return $app['tymon.jwt.provider.storage'];
        };

        $this->app['Tymon\JWTAuth\JWTManager'] = function ($app) {
            return $app['tymon.jwt.manager'];
        };

        $this->app['Tymon\JWTAuth\Blacklist'] = function ($app) {
            return $app['tymon.jwt.blacklist'];
        };

        $this->app['Tymon\JWTAuth\PayloadFactory'] = function ($app) {
            return $app['tymon.jwt.payload.factory'];
        };

        $this->app['Tymon\JWTAuth\Claims\Factory'] = function ($app) {
            return $app['tymon.jwt.claim.factory'];
        };

        $this->app['Tymon\JWTAuth\Validators\PayloadValidator'] = function ($app) {
            return $app['tymon.jwt.validators.payload'];
        };

        $this->app['Tymon\JWTAuth\Validators\PayloadValidator'] = function ($app) {
            return $app['tymon.jwt.validators.payload'];
        };
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        // register providers
        $this->registerUserProvider();
        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerClaimFactory();
        $this->registerJWTManager();

        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerPayloadFactory();
        $this->registerJWTAuthFilter();
        $this->registerJWTCommand();
    }

    /**
     * Register the bindings for the User provider
     */
    public function registerUserProvider()
    {
	    $self = $this;
        $this->app['tymon.jwt.provider.user'] = $this->app->share(function ($app) use ($self) {
            return $app->make($self->config('providers.user'), array($app->make($self->config('user'))));
        });
    }

    /**
     * Register the bindings for the JSON Web Token provider
     */
    public function registerJWTProvider()
    {
    	$self = $this;
        $this->app['tymon.jwt.provider.jwt'] = $this->app->share(function ($app) use ($self) {

            $secret = $self->config('secret');
            $algo = $self->config('algo');
            $provider = $self->config('providers.jwt');

            return $app->make($provider, array($secret, $algo));
        });
    }

    /**
     * Register the bindings for the Auth provider
     */
    public function registerAuthProvider()
    {
	    $self = $this;
        $this->app['tymon.jwt.provider.auth'] = $this->app->share(function ($app) use ($self) {
            return $app->make($self->config('providers.auth'), array($app['auth']));
        });
    }

    /**
     * Register the bindings for the Storage provider
     */
    public function registerStorageProvider()
    {
	    $self = $this;
        $this->app['tymon.jwt.provider.storage'] = $this->app->share(function ($app) use ($self) {
            return $app->make($self->config('providers.storage'), array($app['cache']));
        });
    }

    /**
     * Register the bindings for the Payload Factory
     */
    public function registerClaimFactory()
    {
        $this->app->singleton('tymon.jwt.claim.factory', function () {
            return new Factory();
        });
    }

    /**
     * Register the bindings for the Payload Factory
     */
    public function registerPayloadFactory()
    {
	    $self = $this;
        $this->app['tymon.jwt.payload.factory'] = $this->app->share(function ($app) use ($self) {
            $factory = new PayloadFactory($app['tymon.jwt.claim.factory'], $app['request'], $app['tymon.jwt.validators.payload']);

            return $factory->setTTL($self->config('ttl'));
        });
    }

    /**
     * Register the bindings for the JWT Manager
     */
    public function registerJWTManager()
    {
	    $self = $this;
        $this->app['tymon.jwt.manager'] = $this->app->share(function ($app) use ($self) {

            $instance = new JWTManager(
                $app['tymon.jwt.provider.jwt'],
                $app['tymon.jwt.blacklist'],
                $app['tymon.jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $self->config('blacklist_enabled'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class
     */
    public function registerJWTAuth()
    {
	    $self = $this;
        $this->app['tymon.jwt.auth'] = $this->app->share(function ($app) use ($self) {

            $auth = new JWTAuth(
                $app['tymon.jwt.manager'],
                $app['tymon.jwt.provider.user'],
                $app['tymon.jwt.provider.auth'],
                $app['request']
            );

            return $auth->setIdentifier($self->config('identifier'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class
     */
    public function registerJWTBlacklist()
    {
        $this->app['tymon.jwt.blacklist'] = $this->app->share(function ($app) {
            return new Blacklist($app['tymon.jwt.provider.storage']);
        });
    }

    /**
     * Register the bindings for the payload validator
     */
    public function registerPayloadValidator()
    {
	    $self = $this;
        $this->app['tymon.jwt.validators.payload'] = $this->app->share(function () use ($self) {
            return with(new PayloadValidator)->setRequiredClaims($self->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the 'jwt-auth' filter
     */
    public function registerJWTAuthFilter()
    {
        $this->app['tymon.jwt.filter'] = $this->app->share(function ($app) {
            return new JWTAuthFilter($app['events'], $app['tymon.jwt.auth']);
        });
    }

    /**
     * Register the Artisan command
     */
    public function registerJWTCommand()
    {
        $this->app['tymon.jwt.generate'] = $this->app->share(function ($app) {
            return new JWTGenerateCommand($app['files']);
        });
    }

    /**
     * Helper to get the config values
     * @param string $key
     * @param mixed $default
     * @return string
     */
    public function config($key, $default = null)
    {
        return $this->app['config']->get("jwt.$key", $default);
    }
}
