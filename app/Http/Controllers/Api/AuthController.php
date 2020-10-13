<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\LoginRequest;
use App\Http\Requests\Api\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    const HTTP_OK = Response::HTTP_OK;
    const HTTP_CREATED = Response::HTTP_CREATED;
    const HTTP_UNAUTHORIZED = Response::HTTP_UNAUTHORIZED;
    const HTTP_UNPROCESSABLE_ENTITY = Response::HTTP_UNPROCESSABLE_ENTITY;
    const HTTP_INTERNAL_SERVER_ERROR = Response::HTTP_INTERNAL_SERVER_ERROR;

    public function register(RegisterRequest $request)
    {
        try {
            User::create([
                'name' => $request->get('email'),
                'email' => $request->get('email'),
                'password' => Hash::make($request->get('password')),
            ]);

            return response()->json([
                'message' => 'User registered'
            ], self::HTTP_CREATED);
        } catch (\Throwable $th) {
            if ((int) $th->getCode() === 23000) {
                return response()->json([
                    'message' => 'User already exists',
                ], self::HTTP_UNPROCESSABLE_ENTITY);
            } else {
                return response()->json([
                    'message' => 'Internal server error',
                ], self::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    public function login(LoginRequest $request)
    {
        $credentials = $request->only(['email', 'password']);
        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $token = $user->createToken($user->email)->accessToken;
            return response()->json([
                'data' => [
                    'token' => $token,
                    'user' => $user,
                ],
            ], self::HTTP_OK);
        } else {
            return response()->json([
                'message' => 'Wrong credentials'
            ], self::HTTP_UNPROCESSABLE_ENTITY);
        }
    }

    public function user(Request $request)
    {
        return response()->json([
            'data' => [
                'user' => $request->user()
            ]
        ], self::HTTP_OK);
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();

        return response()->json([
            'message' => 'User logged out'
        ], self::HTTP_OK);
    }
}
