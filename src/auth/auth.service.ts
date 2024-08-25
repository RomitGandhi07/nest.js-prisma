import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { error } from 'console';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    try {
      // Generate the password hash
      const hash = await argon.hash(dto.password);

      // Save the new user in the DB
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;
      // Return the user
      return user;
    } catch (error) {
      // If it is prisma error
      if (error instanceof PrismaClientKnownRequestError) {
        // That means it's the duplicate user
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // Find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // If user does not exist then throw an error
    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    // Compare passwords
    const passwordMatched = await argon.verify(user.hash, dto.password);

    // If password incorrect throw an error
    if (!passwordMatched) {
      throw new ForbiddenException('Credentials incorrect');
    }

    // return
    delete user.hash;
    return user;
  }
}
