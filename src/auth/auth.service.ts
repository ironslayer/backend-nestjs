import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';

import * as bcryptjs from 'bcryptjs';

import { CreateUserDto, UpdateAuthDto, RegisterUserDto, LoginDto } from './dto';


import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name ) 
    private userModel: Model<User>,

    private jwtService: JwtService,
  ){}

  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {
      
      const { password, ...userData } = createUserDto;


      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });
  
      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();

      return user;
      
    } catch (error) {
      if ( error.code === 11000 ) {
        throw new BadRequestException(`${ createUserDto.email } already exist` )
      }
      throw new InternalServerErrorException('Something terrible happen')
    }
  }

  async register(registerUserDto:RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create( registerUserDto );

    return {
      user: user,
      token: this.getJwtToken({ id: user._id! })
    }
  }

  async login( loginDto: LoginDto ): Promise<LoginResponse> {
    const { email, password } = loginDto;

    

    const user = await this.userModel.findOne({ email });
    if ( !user ) {
      throw new UnauthorizedException('Not valid Credentials - email')
    }

    if ( !bcryptjs.compareSync( password, user.password! )) {
      throw new UnauthorizedException('Not valid Credentials - password')
    }

    const { password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id }),
    }

  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ){
    const user = await this.userModel.findById( id );

    if ( !user ) {
      throw new BadRequestException('User does not exist');
    }

    const { password, ...rest } = user.toJSON();
    return rest;
  }

  async reNewToken(id: string): Promise<LoginResponse>{
    const user = await this.findUserById(id);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    return { user, token: this.getJwtToken({ id: user._id }) }
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
