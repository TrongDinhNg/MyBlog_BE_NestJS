import { Body, Controller, Post } from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import { AuthService } from './auth.service';
import { User } from 'src/user/entities/user.entity';
import { LoginUserDto } from './dto/login-user.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('register')
    register(@Body() registerUserDto: RegisterUserDto): Promise<User> {
        console.log('test api register', registerUserDto);
        return this.authService.register(registerUserDto);
    }

    @Post('login')
    login(@Body() loginUserDto: LoginUserDto): Promise<User> {
        return this.authService.login(loginUserDto);
    }
}
