<?php

namespace Tymon\JWTAuth\Providers;

use Illuminate\Support\ServiceProvider;

class BackportServiceProvider extends ServiceProvider
{

	/**
	 * Merge the given configuration with the existing configuration.
	 *
	 * @param $path
	 * @param $key
	 */
	protected function mergeConfigFrom($path, $key)
	{
		$config = $this->app['config']->get($key, array());

		$this->app['config']->set($key, array_merge(require $path, $config));
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		parent::register();
	}
}