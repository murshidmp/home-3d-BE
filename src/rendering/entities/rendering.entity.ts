import { Entity, PrimaryGeneratedColumn, ManyToOne, Column, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Project } from '../../project/entities/project.entity';

@Entity('rendering_logs')
export class RenderingLog {
  @PrimaryGeneratedColumn()
  id: number; // This will be an INT by default

  @ManyToOne(() => User, (user) => user.id, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Project, (project) => project.id, { onDelete: 'CASCADE' })
  project: Project;

  @Column({ type: 'enum', enum: ['Pending', 'Completed', 'Failed'], default: 'Pending' })
  renderStatus: string;

  @Column({ type: 'timestamp', nullable: true })
  renderedAt: Date;

  @CreateDateColumn()
  createdAt: Date;
  
  @UpdateDateColumn()
  updatedAt: Date;
  
    /**
     * When you add @DeleteDateColumn, TypeORM can use "soft delete" 
     * (the record is marked deleted but not physically removed).
     * If you call repository.softRemove(...), it sets the deletedAt value.
     */
  @DeleteDateColumn()
  deletedAt?: Date;
}
