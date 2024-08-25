import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signup() {
    return { message: 'I am signed up' };
  }

  signin() {
    return { message: 'I am signed up' };
  }
}
