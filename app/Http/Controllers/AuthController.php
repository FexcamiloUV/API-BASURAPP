<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
class AuthController extends Controller
{
    public function register(Request $request) {
        try {
            $validatedData = $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:8',
            ]);
            
            $user = User::create([
                'name' => $validatedData['name'],
                'email' => $validatedData['email'],
                'password' => Hash::make($validatedData['password']),
            ]);
            
            $token = $user->createToken('auth_token')->plainTextToken;
            
            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => $user
            ], 201);
            
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Error en el registro',
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function login(Request $request) {
        try {
            $validatedData = $request->validate([
                'email' => 'required|string|email',
                'password' => 'required|string',
            ]);
            if (!Auth::attempt($validatedData)) {
                return response()->json([
                    'error' => 'Credenciales inválidas'
                ], 401);
            }
            
            $user = User::where('email', $validatedData['email'])->firstOrFail();
            $token = $user->createToken('auth_token')->plainTextToken;
            
            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => $user
            ]);
            
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Error en el login',
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function logout(Request $request) {
        try {
            $request->user()->currentAccessToken()->delete();
            
            return response()->json([
                'message' => 'Sesión cerrada exitosamente'
            ]);
            
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Error al cerrar sesión',
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
