// src/project/project.controller.ts
import {
    Controller,
    Post,
    Body,
    Get,
    Param,
    Patch,
    Delete,
    UseGuards,
    Req,
    HttpCode,
    HttpStatus,
    Query,
  } from '@nestjs/common';
  import { AccessTokenGuard } from '../common/guards/accessToken.guard';
  import { ProjectService } from './project.service';
  import { CreateProjectDto } from './dto/create-project.dto';
  import { UpdateProjectDto } from './dto/update-project.dto';
  import { ApiTags, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
  import { ApiSuccessResponse } from '../common/dto/api-response.dto';
import { PaginationQueryDto } from 'src/common/dto/pagination.dto';
  
  @ApiTags('Projects')
  @ApiBearerAuth()
  @UseGuards(AccessTokenGuard)
  @Controller('projects')
  export class ProjectController {
    constructor(private readonly projectService: ProjectService) {}
  
    @Post()
    @HttpCode(HttpStatus.CREATED)
    @ApiResponse({ status: 201, description: 'Project created successfully.' })
    async create(@Req() req: any, @Body() dto: CreateProjectDto) {
      const userId = req.user['sub']; // from your JWT payload
      const project = await this.projectService.createProject(userId, dto);
      return ApiSuccessResponse.of(project, 'Project created');
    }
  
    @Get()
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'List of user projects.' })
    async findAll(@Req() req: any, @Query() paginationQuery: PaginationQueryDto) {
      const userId = req.user['sub'];
      const pagedProjects = await this.projectService.getProjectsForUser(userId, paginationQuery);
      return ApiSuccessResponse.of(pagedProjects, 'Projects fetched successfully');
    }
  
    @Get(':id')
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'Project fetched successfully.' })
    async findOne(@Req() req: any, @Param('id') id: number) {
      const userId = req.user['sub'];
      const project = await this.projectService.getProjectById(userId, id);
      return ApiSuccessResponse.of(project, 'Project fetched');
    }
  
    @Patch(':id')
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'Project updated successfully.' })
    async update(
      @Req() req: any,
      @Param('id') id: number,
      @Body() dto: UpdateProjectDto,
    ) {
      const userId = req.user['sub'];
      const project = await this.projectService.updateProject(userId, id, dto);
      return ApiSuccessResponse.of(project, 'Project updated');
    }
  
    @Delete(':id')
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'Project deleted (soft) successfully.' })
    async remove(@Req() req: any, @Param('id') id: number) {
      const userId = req.user['sub'];
      await this.projectService.deleteProject(userId, id);
      return ApiSuccessResponse.of(null, 'Project deleted');
    }
  }
  